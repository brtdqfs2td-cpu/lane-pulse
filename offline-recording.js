"use strict";

// ---------------------------------------------------------------------
// Lane Pulse — Polar offline-recording retrieval (PMD + PSFTP)
//
// Reverse-engineered from Polar's own open-source BLE SDK
// (github.com/polarofficial/polar-ble-sdk, Apache-2.0), reading the
// actual Kotlin implementation directly rather than porting any
// third-party unofficial code. Covers exactly what Lane Pulse needs:
// pulling an offline-recorded ACC (.REC) file off a Verity Sense and
// decoding it into timestamped accelerometer samples. Does not cover
// PPG/ECG/GYRO/MAG or encrypted recordings (Lane Pulse always requests
// SecurityStrategy.NONE when it starts a recording, since it controls
// that call itself).
//
// This file is pure logic + a thin GATT orchestration layer. Every
// pure function (protobuf, RFC76 framing, delta decompression, ACC
// decode, timestamp interpolation) is unit-testable in plain Node
// with no browser/BLE involved -- see offline-recording.test.js.
// ---------------------------------------------------------------------

(function (root, factory) {
  if (typeof module === "object" && module.exports) {
    module.exports = factory();
  } else {
    root.LanePulseOffline = factory();
  }
})(typeof self !== "undefined" ? self : this, function () {

  // =====================================================================
  // GATT UUIDs (exact, from BlePsFtpUtils.kt / BlePMDClient.kt)
  // =====================================================================
  var PSFTP_SERVICE_UUID = "0000feee-0000-1000-8000-00805f9b34fb";
  // The MTU characteristic is the one actually used for GET-style
  // request/response (write the request here, response notifications
  // arrive here too -- confirmed directly from BlePsFtpClient.kt's
  // request() and processServiceData()). D2H/H2D exist for a separate
  // notification channel and file-upload (PUT) support respectively --
  // neither is needed for what Lane Pulse does (read-only GET/list).
  var PSFTP_MTU_CHAR_UUID = "fb005c51-02e7-f387-1cad-8acd2d8df0c8";
  var PSFTP_D2H_CHAR_UUID = "fb005c52-02e7-f387-1cad-8acd2d8df0c8"; // unused by Lane Pulse
  var PSFTP_H2D_CHAR_UUID = "fb005c53-02e7-f387-1cad-8acd2d8df0c8"; // unused by Lane Pulse (PUT only)
  var PMD_SERVICE_UUID = "fb005c80-02e7-f387-1cad-8acd2d8df0c8";
  var PMD_CONTROL_CHAR_UUID = "fb005c81-02e7-f387-1cad-8acd2d8df0c8";
  var PMD_DATA_CHAR_UUID = "fb005c82-02e7-f387-1cad-8acd2d8df0c8";

  // =====================================================================
  // Varint + minimal protobuf (proto2 wire format) -- hand-rolled rather
  // than pulling in protobufjs, to keep this a dependency-free, offline-
  // capable static file like the rest of the project. Only implements
  // what PbPFtpOperation (encode) and PbPFtpDirectory/PbPFtpEntry
  // (decode) actually need.
  // =====================================================================
  function encodeVarint(value) {
    var bytes = [];
    var v = value >>> 0;
    while (v > 0x7f) {
      bytes.push((v & 0x7f) | 0x80);
      v >>>= 7;
    }
    bytes.push(v & 0x7f);
    return bytes;
  }

  function readVarint(bytes, offset) {
    var result = 0;
    var shift = 0;
    var pos = offset;
    for (;;) {
      var b = bytes[pos];
      pos += 1;
      result |= (b & 0x7f) << shift;
      if ((b & 0x80) === 0) break;
      shift += 7;
    }
    return { value: result >>> 0, offset: pos };
  }

  function encodeProtoString(fieldNumber, str) {
    var tag = (fieldNumber << 3) | 2; // wire type 2: length-delimited
    var strBytes = Array.prototype.slice.call(new TextEncoder().encode(str));
    return encodeVarint(tag).concat(encodeVarint(strBytes.length)).concat(strBytes);
  }

  function encodeProtoVarintField(fieldNumber, value) {
    var tag = (fieldNumber << 3) | 0; // wire type 0: varint
    return encodeVarint(tag).concat(encodeVarint(value));
  }

  // PbPFtpOperation { required Command command = 1; required string path = 2; }
  // Command: GET=0, PUT=1, MERGE=2, REMOVE=3
  var PFTP_COMMAND = { GET: 0, PUT: 1, MERGE: 2, REMOVE: 3 };
  function encodePbPFtpOperation(command, path) {
    var bytes = encodeProtoVarintField(1, command).concat(encodeProtoString(2, path));
    return new Uint8Array(bytes);
  }

  // Generic-enough decoder for PbPFtpDirectory { repeated PbPFtpEntry entries = 1; }
  // and PbPFtpEntry { required string name = 1; required uint64 size = 2; ... }.
  // Skips any field it doesn't recognize (dates, etc.) rather than fully
  // modeling every message -- Lane Pulse only needs name + size.
  function skipField(bytes, offset, wireType) {
    if (wireType === 0) { return readVarint(bytes, offset).offset; }
    if (wireType === 1) { return offset + 8; }
    if (wireType === 2) {
      var len = readVarint(bytes, offset);
      return len.offset + len.value;
    }
    if (wireType === 5) { return offset + 4; }
    throw new Error("Unknown protobuf wire type " + wireType + " at offset " + offset);
  }

  function decodePbPFtpEntry(bytes) {
    var entry = { name: null, size: 0 };
    var offset = 0;
    while (offset < bytes.length) {
      var tagResult = readVarint(bytes, offset);
      var tag = tagResult.value;
      offset = tagResult.offset;
      var fieldNumber = tag >>> 3;
      var wireType = tag & 0x07;
      if (fieldNumber === 1 && wireType === 2) {
        var lenR = readVarint(bytes, offset);
        var strBytes = bytes.slice(lenR.offset, lenR.offset + lenR.value);
        entry.name = new TextDecoder().decode(new Uint8Array(strBytes));
        offset = lenR.offset + lenR.value;
      } else if (fieldNumber === 2 && wireType === 0) {
        var sizeR = readVarint(bytes, offset);
        entry.size = sizeR.value;
        offset = sizeR.offset;
      } else {
        offset = skipField(bytes, offset, wireType);
      }
    }
    return entry;
  }

  function decodePbPFtpDirectory(bytes) {
    var entries = [];
    var offset = 0;
    while (offset < bytes.length) {
      var tagResult = readVarint(bytes, offset);
      var tag = tagResult.value;
      offset = tagResult.offset;
      var fieldNumber = tag >>> 3;
      var wireType = tag & 0x07;
      if (fieldNumber === 1 && wireType === 2) {
        var lenR = readVarint(bytes, offset);
        var entryBytes = bytes.slice(lenR.offset, lenR.offset + lenR.value);
        entries.push(decodePbPFtpEntry(entryBytes));
        offset = lenR.offset + lenR.value;
      } else {
        offset = skipField(bytes, offset, wireType);
      }
    }
    return entries;
  }

  // =====================================================================
  // RFC60 request envelope + RFC76 chunked transport (from BlePsFtpUtils.kt)
  // =====================================================================
  var RFC76_HEADER_SIZE = 1;
  var RFC76_STATUS_ERROR_OR_RESPONSE = 0x00;
  var RFC76_STATUS_LAST = 0x01;
  var RFC76_STATUS_MORE = 0x03;

  // Wraps a protobuf-encoded PbPFtpOperation as an RFC60 "REQUEST" message:
  // 2-byte little-endian-ish length header (15-bit, MSB of byte1 reserved),
  // followed by the header bytes themselves. No `data` payload for GET/REMOVE.
  function makeRfc60Request(headerBytes) {
    var len = headerBytes.length;
    var b0 = len & 0x00ff;
    var b1 = (len & 0x7f00) >> 8;
    return [b0, b1].concat(Array.prototype.slice.call(headerBytes));
  }

  // Splits a full RFC60 message into MTU-sized RFC76 air packets.
  // Each packet: 1 header byte (bit0 = "next", bits1-2 = MORE(0x06)/LAST(0x02)
  // status flag, bits4-7 = 4-bit rolling sequence number) + payload chunk.
  function buildRfc76Frames(messageBytes, mtuSize) {
    var frames = [];
    var seq = 0;
    var pos = 0;
    var next = 0;
    var maxChunk = mtuSize - RFC76_HEADER_SIZE;
    do {
      var remaining = messageBytes.length - pos;
      var isLast = remaining <= maxChunk;
      var chunkLen = isLast ? remaining : maxChunk;
      var flag = isLast ? 0x02 : 0x06; // LAST vs MORE
      var header = (next | flag | (seq << 4)) & 0xff;
      var frame = [header].concat(Array.prototype.slice.call(messageBytes, pos, pos + chunkLen));
      frames.push(new Uint8Array(frame));
      pos += chunkLen;
      next = 1;
      seq = (seq + 1) & 0x0f;
    } while (pos < messageBytes.length);
    if (frames.length === 0) {
      // zero-length message still needs one frame (e.g. GET with no header edge case)
      frames.push(new Uint8Array([0x02]));
    }
    return frames;
  }

  // Reassembles incoming RFC76 notification packets into a complete
  // response. Call with each packet as it arrives; returns
  // { done: false } while more are expected, or
  // { done: true, error: <code>|null, payload: Uint8Array } once complete.
  function createRfc76Reassembler() {
    var chunks = [];
    return {
      pushPacket: function (packet) {
        var headerByte = packet[0];
        var status = (headerByte >> 1) & 0x03;
        var payload = packet.slice(RFC76_HEADER_SIZE);
        if (status === RFC76_STATUS_ERROR_OR_RESPONSE) {
          var errorCode = (payload[0] | (payload[1] << 8)) & 0xffff;
          return { done: true, error: errorCode, payload: null };
        }
        chunks.push(payload);
        if (status === RFC76_STATUS_LAST) {
          var total = 0;
          for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
          var out = new Uint8Array(total);
          var off = 0;
          for (var j = 0; j < chunks.length; j++) { out.set(chunks[j], off); off += chunks[j].length; }
          return { done: true, error: null, payload: out };
        }
        return { done: false };
      }
    };
  }

  // =====================================================================
  // PMD data frame envelope (from PmdDataFrame.kt) + ACC decode
  // (from AccData.kt) + timestamp interpolation (from PmdTimeStampUtils.kt)
  // =====================================================================
  function readSignedInt(bytes, offset, len) {
    var value = 0;
    for (var i = len - 1; i >= 0; i--) value = (value << 8) | bytes[offset + i];
    // sign-extend if the top bit of the most-significant byte is set
    var signBit = 1 << (len * 8 - 1);
    if (len < 4 && (value & signBit)) value -= (1 << (len * 8));
    return value;
  }

  function parsePmdDataFrameEnvelope(bytes) {
    if (bytes.length < 10) throw new Error("PMD data frame too short: " + bytes.length + " bytes");
    var measurementType = bytes[0];
    var timeStamp = 0n;
    for (var i = 7; i >= 0; i--) timeStamp = (timeStamp << 8n) | BigInt(bytes[1 + i]);
    var frameTypeByte = bytes[9];
    var isCompressedFrame = (frameTypeByte & 0x80) !== 0;
    var frameType = frameTypeByte & 0x7f;
    return {
      measurementType: measurementType,
      timeStamp: timeStamp,
      frameType: frameType,
      isCompressedFrame: isCompressedFrame,
      dataContent: bytes.slice(10)
    };
  }

  // Delta-frame decompression (port of BlePMDClient.parseDeltaFramesAll):
  // a reference sample per channel, then repeated blocks of bit-packed
  // deltas (LSB-first within each byte) that accumulate onto the previous
  // sample.
  function parseDeltaFramesAll(bytes, channels, resolutionBits) {
    var refByteLen = Math.ceil(resolutionBits / 8);
    var refSamples = [];
    for (var c = 0; c < channels; c++) {
      refSamples.push(readSignedInt(bytes, c * refByteLen, refByteLen));
    }
    var samples = [refSamples];
    var offset = channels * refByteLen;

    while (offset < bytes.length) {
      var deltaSize = bytes[offset]; offset += 1;
      var sampleCount = bytes[offset]; offset += 1;
      var bitLength = sampleCount * deltaSize * channels;
      var byteLength = Math.ceil(bitLength / 8);
      var deltaBlock = bytes.slice(offset, offset + byteLength);
      offset += byteLength;

      // unpack bits LSB-first across the whole block, deltaSize bits per value
      var bits = [];
      for (var bi = 0; bi < deltaBlock.length; bi++) {
        for (var bit = 0; bit < 8; bit++) bits.push((deltaBlock[bi] & (1 << bit)) !== 0);
      }
      var mask = -1 << (deltaSize - 1);
      var bitOffset = 0;
      for (var s = 0; s < sampleCount; s++) {
        var lastSample = samples[samples.length - 1];
        var nextSample = [];
        for (var ch = 0; ch < channels; ch++) {
          var value = 0;
          for (var k = 0; k < deltaSize; k++) {
            if (bits[bitOffset + k]) value |= (1 << k);
          }
          bitOffset += deltaSize;
          if ((value & mask) !== 0) value |= mask; // sign-extend
          nextSample.push(lastSample[ch] + value);
        }
        samples.push(nextSample);
      }
    }
    return samples;
  }

  // Assigns a nanosecond-ish timestamp to each sample in a frame, given the
  // frame's own end timestamp, the previous frame's end timestamp (0n if
  // this is the first frame), sample count, and nominal sample rate.
  function getTimeStamps(previousFrameTimeStamp, frameTimeStamp, samplesSize, sampleRate) {
    if (samplesSize <= 0) throw new Error("samplesSize must be > 0");
    var delta;
    if (previousFrameTimeStamp === 0n) {
      delta = (1 / sampleRate) * 1e9;
    } else {
      var timeInBetween = Number(frameTimeStamp - previousFrameTimeStamp);
      if (timeInBetween <= 0) throw new Error("Non-positive timestamp delta between frames");
      delta = timeInBetween / samplesSize;
    }
    var startTimeStamp;
    if (previousFrameTimeStamp === 0n) {
      startTimeStamp = Number(frameTimeStamp) - delta * (samplesSize - 1);
    } else {
      startTimeStamp = Number(previousFrameTimeStamp) + delta;
    }
    var out = [];
    for (var i = 0; i < samplesSize - 1; i++) out.push(BigInt(Math.round(startTimeStamp + delta * i)));
    out.push(frameTimeStamp);
    return out;
  }

  // ACC-specific decode, dispatching on frame type + compressed flag.
  // Ported from AccData.kt -- only the paths Lane Pulse needs (types 0-2
  // raw, types 0-1 compressed; that covers every Verity Sense config).
  function decodeAccFrame(envelope, previousTimeStamp, factor, sampleRate) {
    var samples = [];
    var raw;
    if (envelope.isCompressedFrame) {
      if (envelope.frameType === 0) {
        raw = parseDeltaFramesAll(envelope.dataContent, 3, 16);
        var accFactor = factor * 1000; // arrives in G, convert to milliG
        var ts0 = getTimeStamps(previousTimeStamp, envelope.timeStamp, raw.length, sampleRate);
        for (var i = 0; i < raw.length; i++) {
          samples.push({ timeStamp: ts0[i], x: Math.round(raw[i][0] * accFactor), y: Math.round(raw[i][1] * accFactor), z: Math.round(raw[i][2] * accFactor) });
        }
      } else if (envelope.frameType === 1) {
        raw = parseDeltaFramesAll(envelope.dataContent, 3, 16);
        var ts1 = getTimeStamps(previousTimeStamp, envelope.timeStamp, raw.length, sampleRate);
        for (var j = 0; j < raw.length; j++) {
          var scale = factor !== 1.0 ? factor : 1;
          samples.push({ timeStamp: ts1[j], x: Math.round(raw[j][0] * scale), y: Math.round(raw[j][1] * scale), z: Math.round(raw[j][2] * scale) });
        }
      } else {
        throw new Error("ACC compressed frame type " + envelope.frameType + " not supported");
      }
    } else {
      var byteWidths = { 0: 1, 1: 2, 2: 3 };
      var step = byteWidths[envelope.frameType];
      if (!step) throw new Error("ACC raw frame type " + envelope.frameType + " not supported");
      var sampleByteSize = step * 3;
      if (envelope.dataContent.length === 0 || envelope.dataContent.length % sampleByteSize !== 0) {
        throw new Error("ACC raw dataContent size " + envelope.dataContent.length + " is not a multiple of " + sampleByteSize);
      }
      var count = envelope.dataContent.length / sampleByteSize;
      var ts2 = getTimeStamps(previousTimeStamp, envelope.timeStamp, count, sampleRate);
      var offset = 0;
      for (var k = 0; k < count; k++) {
        var x = readSignedInt(envelope.dataContent, offset, step); offset += step;
        var y = readSignedInt(envelope.dataContent, offset, step); offset += step;
        var z = readSignedInt(envelope.dataContent, offset, step); offset += step;
        samples.push({ timeStamp: ts2[k], x: x, y: y, z: z });
      }
    }
    return samples;
  }

  // =====================================================================
  // Directory path convention (from PolarOfflineRecordingApiImpl.kt):
  // /U/0/{YYYYMMDD}/R/{HHMMSS}/{TYPE}###.REC
  // =====================================================================
  var OFFLINE_ROOT_PATH = "/U/0/";
  function measurementTypeFromFileName(fileName) {
    var withoutExt = fileName.replace(/\.[^.]+$/, "");
    var typePart = withoutExt.replace(/\d+/g, "");
    return typePart; // "ACC", "GYRO", "MAG", "PPG", "PPI", "HR", "TEMP", "SKINTEMP"
  }

  // =====================================================================
  // .REC file metadata header (from OfflineRecordingData.kt's
  // parseMetaData/parseHeader). Verified byte-for-byte against a real
  // recording pulled off a Verity Sense: magic and the readable
  // start-time string both landed exactly where this expects. Only
  // handles SecurityStrategy.NONE (0x00) -- Lane Pulse always requests
  // NONE when it starts a recording, so XOR/AES128/AES256 paths (which
  // need a device-specific secret Lane Pulse never has) are explicitly
  // unsupported rather than silently wrong.
  // =====================================================================
  var OFFLINE_HEADER_MAGIC = 0x3d7c4c2b;
  var OFFLINE_HEADER_LENGTH = 16;
  var DATE_TIME_LENGTH = 20;

  function readUint32LE(bytes, offset) {
    return (bytes[offset] | (bytes[offset + 1] << 8) | (bytes[offset + 2] << 16) | (bytes[offset + 3] << 24)) >>> 0;
  }

  // Returns { securityStrategy, magic, version, startTimeRaw, dataOffset }.
  // dataOffset is where the actual PMD frame stream begins in the file.
  function parseOfflineRecordingHeader(bytes) {
    var offset = 0;
    var securityStrategy = bytes[offset]; offset += 1;
    if (securityStrategy !== 0) {
      throw new Error("Offline recording uses security strategy " + securityStrategy + " (not NONE) -- unsupported, Lane Pulse has no secret for it");
    }

    var magic = readUint32LE(bytes, offset);
    if (magic !== OFFLINE_HEADER_MAGIC) {
      throw new Error("Offline recording has wrong signature: expected 0x" + OFFLINE_HEADER_MAGIC.toString(16) + ", got 0x" + magic.toString(16));
    }
    var version = readUint32LE(bytes, offset + 4);
    offset += OFFLINE_HEADER_LENGTH; // magic(4) + version(4) + free(4) + eswHash(4)

    var startTimeBytes = bytes.slice(offset, offset + DATE_TIME_LENGTH);
    var startTimeRaw = new TextDecoder().decode(new Uint8Array(startTimeBytes)).replace(/\0+$/, "");
    offset += DATE_TIME_LENGTH;

    var settingsLength = bytes[offset]; offset += 1;
    var settingsBytes = bytes.slice(offset, offset + settingsLength); // raw for now -- PmdSetting decoding is the next piece
    offset += settingsLength;

    var securityInfoLength = bytes[offset]; offset += 1;
    offset += securityInfoLength; // 0 for SecurityStrategy.NONE

    // The fixed byte size of every frame in this file -- frames are packed
    // back-to-back at exactly this size, with no other delimiter (confirmed
    // from OfflineRecordingData.kt's parseData: `decryptedData.slice(offset
    // until packetSize + offset)` in a loop, offset += packetSize each time).
    var dataPayloadSize = bytes[offset] | (bytes[offset + 1] << 8);
    offset += 2;

    return {
      securityStrategy: securityStrategy,
      magic: magic,
      version: version,
      startTimeRaw: startTimeRaw,
      settingsLength: settingsLength,
      settingsBytes: settingsBytes,
      securityInfoLength: securityInfoLength,
      dataPayloadSize: dataPayloadSize,
      dataOffset: offset
    };
  }

  // Splits the frame stream (starting at header.dataOffset) into individual
  // fixed-size frames using header.dataPayloadSize, per parseData's slicing
  // logic. Returns an array of Uint8Array, one per frame.
  // strideOverride lets the caller advance by a different amount than the
  // slice size -- needed when the real gap between frames doesn't match
  // header.dataPayloadSize exactly (see determineRealFrameStride below).
  function splitFrameStream(fileBytes, header, strideOverride) {
    var frames = [];
    var packetSize = header.dataPayloadSize;
    var stride = strideOverride || packetSize;
    if (!packetSize || packetSize <= 0) return frames;
    var offset = header.dataOffset;
    while (offset + packetSize <= fileBytes.length) {
      frames.push(fileBytes.slice(offset, offset + packetSize));
      offset += stride;
    }
    return frames;
  }

  // Verifies (and corrects, if needed) the real byte gap between frame 0
  // and frame 1 by scanning near where the documented dataPayloadSize says
  // frame 1 should start. Real-hardware testing found a file where the
  // true stride was 2 bytes larger than the documented value (likely an
  // older on-device format variant -- this 2017 test recording predates
  // the current SDK source by years) -- rather than hardcode that offset,
  // this measures it per-file and falls back to the documented value if
  // no clear candidate is found nearby.
  function determineRealFrameStride(fileBytes, header) {
    var documented = header.dataPayloadSize;
    if (header.dataOffset + documented > fileBytes.length) return documented;
    var envelope0 = parsePmdDataFrameEnvelope(fileBytes.slice(header.dataOffset, header.dataOffset + documented));
    var expectedOffset = header.dataOffset + documented;
    var searchFrom = Math.max(header.dataOffset + 1, expectedOffset - 20);
    var searchTo = expectedOffset + 20;
    var candidates = scanForFrameBoundaries(fileBytes, searchFrom, searchTo, envelope0.measurementType);
    if (!candidates.length) return documented;
    candidates.sort(function (a, b) { return Math.abs(a.offset - expectedOffset) - Math.abs(b.offset - expectedOffset); });
    return candidates[0].offset - header.dataOffset;
  }

  // Debugging aid: searches file bytes for offsets whose envelope looks
  // plausible (measurementType matches expectedMeasurementType exactly,
  // frameType's low 7 bits fall in 0-14) within [fromOffset, toOffset).
  // Used to empirically find the real per-frame size against a real file
  // when the documented dataPayloadSize doesn't seem to produce aligned
  // frames -- see the "Scan for frame boundary" debug button.
  function scanForFrameBoundaries(fileBytes, fromOffset, toOffset, expectedMeasurementType) {
    var candidates = [];
    var end = Math.min(toOffset, fileBytes.length - 10);
    for (var offset = fromOffset; offset < end; offset++) {
      if (fileBytes[offset] !== expectedMeasurementType) continue;
      var frameType = fileBytes[offset + 9] & 0x7f;
      if (frameType <= 14) {
        candidates.push({ offset: offset, frameType: frameType, compressed: (fileBytes[offset + 9] & 0x80) !== 0 });
      }
    }
    return candidates;
  }

  // =====================================================================
  // PmdSetting decoding (from PmdSetting.kt): a simple repeated
  // [typeId(1)][count(1)][count x fieldSize bytes] structure. Only the
  // fields Lane Pulse's ACC decode actually needs are named here; the rest
  // are still parsed generically (so DERIVED_MEASUREMENT_METHOD can be
  // detected) but not individually documented.
  // =====================================================================
  var PMD_SETTING_TYPE = {
    0: { name: "SAMPLE_RATE", fieldSize: 2 },
    1: { name: "RESOLUTION", fieldSize: 2 },
    2: { name: "RANGE", fieldSize: 2 },
    3: { name: "RANGE_MILLIUNIT", fieldSize: 4 },
    4: { name: "CHANNELS", fieldSize: 1 },
    5: { name: "FACTOR", fieldSize: 4 }, // IEEE754 float bits, not a plain int
    6: { name: "SECURITY", fieldSize: 16 },
    7: { name: "DERIVED_MEASUREMENT_METHOD", fieldSize: 1 },
    8: { name: "SOURCE_MEASUREMENT_TYPE", fieldSize: 1 },
    9: { name: "SOURCE_MEASUREMENT_SAMPLE_RATE", fieldSize: 2 },
    10: { name: "SOURCE_MEASUREMENT_RANGE", fieldSize: 4 },
    11: { name: "DERIVED_MEASUREMENT_TIME_WINDOW", fieldSize: 4 },
    12: { name: "DERIVED_MEASUREMENT_SETTINGS_GROUP_ID", fieldSize: 1 }
  };

  function readFloat32LE(bytes, offset) {
    var buf = new ArrayBuffer(4);
    var view = new DataView(buf);
    for (var i = 0; i < 4; i++) view.setUint8(i, bytes[offset + i]);
    return view.getFloat32(0, true);
  }

  function parsePmdSettings(bytes) {
    var settings = {};
    if (!bytes || bytes.length <= 1) return settings;
    var offset = 0;
    while (offset < bytes.length) {
      var typeId = bytes[offset]; offset += 1;
      var typeInfo = PMD_SETTING_TYPE[typeId];
      if (!typeInfo) throw new Error("Unknown PmdSettingType ID: " + typeId);
      var count = bytes[offset]; offset += 1;
      var values = [];
      for (var i = 0; i < count; i++) {
        values.push(typeInfo.name === "FACTOR" ? readFloat32LE(bytes, offset) : readSignedInt(bytes, offset, typeInfo.fieldSize));
        offset += typeInfo.fieldSize;
      }
      settings[typeInfo.name] = values;
    }
    return settings;
  }

  // =====================================================================
  // Full file decode: header -> settings -> fixed-size frame split -> ACC
  // decode of each frame, threading the running timestamp between frames
  // exactly like PolarOfflineRecordingApiImpl's parseData does. Explicitly
  // refuses a "derived measurement" recording (DERIVED_MEASUREMENT_METHOD
  // present) rather than silently mis-decoding it as raw ACC -- that's a
  // materially different frame format Lane Pulse doesn't handle yet.
  // =====================================================================
  var VERITY_SENSE_DEFAULT_ACC_SAMPLE_RATE = 52; // Hz, matches the documented default config

  function decodeAccRecordingFile(fileBytes) {
    var header = parseOfflineRecordingHeader(fileBytes);
    var settings = parsePmdSettings(header.settingsBytes);

    if (settings.DERIVED_MEASUREMENT_METHOD && settings.DERIVED_MEASUREMENT_METHOD.length) {
      throw new Error("This recording is a derived-measurement recording (methods: " +
        settings.DERIVED_MEASUREMENT_METHOD.join(",") + ") -- not supported, needs different decode logic than raw ACC");
    }

    var sampleRate = (settings.SAMPLE_RATE && settings.SAMPLE_RATE[0]) || VERITY_SENSE_DEFAULT_ACC_SAMPLE_RATE;
    var factor = (settings.FACTOR && settings.FACTOR[0] !== undefined) ? settings.FACTOR[0] : 1.0;

    var frameStride = determineRealFrameStride(fileBytes, header);
    var frames = splitFrameStream(fileBytes, header, frameStride);
    var allSamples = [];
    var previousTimeStamp = 0n;
    frames.forEach(function (frameBytes, frameIndex) {
      var envelope;
      try {
        envelope = parsePmdDataFrameEnvelope(frameBytes);
        var samples = decodeAccFrame(envelope, previousTimeStamp, factor, sampleRate);
        previousTimeStamp = envelope.timeStamp;
        allSamples = allSamples.concat(samples);
      } catch (err) {
        var firstBytes = Array.prototype.slice.call(frameBytes, 0, 10)
          .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join(" ");
        var fileOffset = header.dataOffset + frameIndex * frameStride;
        throw new Error(err.message + " [frame " + frameIndex + "/" + frames.length +
          ", file offset " + fileOffset + ", envelope bytes: " + firstBytes + "]");
      }
    });

    return { header: header, settings: settings, sampleRate: sampleRate, factor: factor, frameStride: frameStride, frameCount: frames.length, samples: allSamples };
  }

  // =====================================================================
  // GATT orchestration -- browser-only (uses navigator.bluetooth
  // characteristic objects), NOT covered by the Node unit tests. This is
  // the one part of the module that can only be verified against real
  // hardware. Confirmed from BlePsFtpClient.kt: GET-style request/response
  // both happen on the MTU characteristic -- write the RFC76-framed
  // request there, and the response arrives as notifications on that same
  // characteristic. D2H/H2D are not used for this (D2H is a separate
  // notification channel, H2D is for file uploads) -- deliberately not
  // touched here to keep the first real test as small a surface as
  // possible.
  //
  // MTU chunk size: Web Bluetooth doesn't expose the real negotiated ATT
  // MTU reliably, so this conservatively uses 20 bytes (the guaranteed-
  // safe default BLE payload) rather than guessing higher. Correct in
  // every case, just more chunking overhead than an optimal negotiated
  // size would need -- fine to tune later once real hardware confirms
  // what's actually negotiated.
  // =====================================================================
  var PSFTP_CHUNK_SIZE = 20;
  var PSFTP_TIMEOUT_MS = 15000;

  // Assumes the caller has already started notifications on mtuChar --
  // deliberately does NOT call startNotifications() itself. Re-enabling an
  // already-active notification subscription is its own GATT operation,
  // and issuing it on every single request was colliding with Windows'
  // one-GATT-operation-in-flight-per-device limit. See preparePsftpChannel.
  function psftpRequest(mtuChar, command, path) {
    var header = encodePbPFtpOperation(command, path);
    var message = new Uint8Array(makeRfc60Request(header));
    var frames = buildRfc76Frames(message, PSFTP_CHUNK_SIZE);
    var reassembler = createRfc76Reassembler();

    return new Promise(function (resolve, reject) {
      var settled = false;
      var timeoutId = setTimeout(function () {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error("PSFTP request timed out after " + PSFTP_TIMEOUT_MS + "ms (path: " + path + ")"));
      }, PSFTP_TIMEOUT_MS);

      function cleanup() {
        clearTimeout(timeoutId);
        mtuChar.removeEventListener("characteristicvaluechanged", onNotify);
      }

      function onNotify(evt) {
        if (settled) return;
        var packet = new Uint8Array(evt.target.value.buffer);
        var result;
        try {
          result = reassembler.pushPacket(packet);
        } catch (err) {
          settled = true;
          cleanup();
          reject(err);
          return;
        }
        if (result.done) {
          settled = true;
          cleanup();
          if (result.error !== null && result.error !== 0) {
            reject(new Error("PSFTP error code " + result.error + " (path: " + path + ")"));
          } else {
            resolve(result.payload);
          }
        }
      }

      mtuChar.addEventListener("characteristicvaluechanged", onNotify);
      var i = 0;
      function sendNext() {
        if (i >= frames.length) return Promise.resolve();
        return mtuChar.writeValueWithoutResponse(frames[i]).then(function () {
          i++;
          return sendNext();
        });
      }
      sendNext().catch(function (err) {
        if (settled) return;
        settled = true;
        cleanup();
        reject(err);
      });
    });
  }

  // Call once per device connection: resolves the PSFTP service, its MTU
  // characteristic, and turns on notifications a single time. Every
  // psftpRequest afterward reuses this same characteristic instance.
  function preparePsftpChannel(gattServer) {
    return gattServer.getPrimaryService(PSFTP_SERVICE_UUID)
      .then(function (service) { return service.getCharacteristic(PSFTP_MTU_CHAR_UUID); })
      .then(function (mtuChar) {
        return mtuChar.startNotifications().then(function () { return mtuChar; });
      });
  }

  function listDirectory(mtuChar, path) {
    return psftpRequest(mtuChar, PFTP_COMMAND.GET, path).then(function (payload) {
      return decodePbPFtpDirectory(payload);
    });
  }

  function getFile(mtuChar, path) {
    return psftpRequest(mtuChar, PFTP_COMMAND.GET, path);
  }

  // Recursively walks /U/0/{date}/R/{time}/ and returns every entry whose
  // name maps to an ACC recording, with its full path attached. Walks one
  // directory at a time -- Web Bluetooth allows only one GATT operation in
  // flight per device, so firing sibling directory listings concurrently
  // (e.g. via Promise.all) fails with "GATT operation already in progress."
  function findOfflineAccRecordings(mtuChar) {
    function walk(path) {
      return listDirectory(mtuChar, path).then(function (entries) {
        var results = [];
        var directories = entries.filter(function (entry) {
          return entry.name.charAt(entry.name.length - 1) === "/";
        });
        entries.forEach(function (entry) {
          if (entry.name.charAt(entry.name.length - 1) !== "/" && measurementTypeFromFileName(entry.name) === "ACC") {
            results.push({ path: path + entry.name, size: entry.size });
          }
        });
        return directories.reduce(function (chain, dirEntry) {
          return chain.then(function () {
            return walk(path + dirEntry.name).then(function (subResults) {
              results = results.concat(subResults);
            });
          });
        }, Promise.resolve()).then(function () { return results; });
      });
    }
    return walk(OFFLINE_ROOT_PATH);
  }

  return {
    // GATT UUIDs
    PSFTP_SERVICE_UUID: PSFTP_SERVICE_UUID,
    PSFTP_MTU_CHAR_UUID: PSFTP_MTU_CHAR_UUID,
    PSFTP_D2H_CHAR_UUID: PSFTP_D2H_CHAR_UUID,
    PSFTP_H2D_CHAR_UUID: PSFTP_H2D_CHAR_UUID,
    PMD_SERVICE_UUID: PMD_SERVICE_UUID,
    PMD_CONTROL_CHAR_UUID: PMD_CONTROL_CHAR_UUID,
    PMD_DATA_CHAR_UUID: PMD_DATA_CHAR_UUID,
    OFFLINE_ROOT_PATH: OFFLINE_ROOT_PATH,

    // Protobuf (exposed for testing + orchestration layer)
    PFTP_COMMAND: PFTP_COMMAND,
    encodeVarint: encodeVarint,
    readVarint: readVarint,
    encodePbPFtpOperation: encodePbPFtpOperation,
    decodePbPFtpDirectory: decodePbPFtpDirectory,
    decodePbPFtpEntry: decodePbPFtpEntry,

    // Transport
    makeRfc60Request: makeRfc60Request,
    buildRfc76Frames: buildRfc76Frames,
    createRfc76Reassembler: createRfc76Reassembler,

    // PMD / ACC decode
    parsePmdDataFrameEnvelope: parsePmdDataFrameEnvelope,
    parseDeltaFramesAll: parseDeltaFramesAll,
    getTimeStamps: getTimeStamps,
    decodeAccFrame: decodeAccFrame,
    readSignedInt: readSignedInt,
    measurementTypeFromFileName: measurementTypeFromFileName,
    OFFLINE_HEADER_MAGIC: OFFLINE_HEADER_MAGIC,
    parseOfflineRecordingHeader: parseOfflineRecordingHeader,
    splitFrameStream: splitFrameStream,
    scanForFrameBoundaries: scanForFrameBoundaries,
    determineRealFrameStride: determineRealFrameStride,
    parsePmdSettings: parsePmdSettings,
    readFloat32LE: readFloat32LE,
    decodeAccRecordingFile: decodeAccRecordingFile,

    // GATT orchestration (browser-only, untested by the Node suite)
    psftpRequest: psftpRequest,
    preparePsftpChannel: preparePsftpChannel,
    listDirectory: listDirectory,
    getFile: getFile,
    findOfflineAccRecordings: findOfflineAccRecordings
  };
});
