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
  // Also exposes stats() -- packet/byte counters, last status/seq seen, and
  // the first sequence-number discontinuity if any -- purely for diagnosing
  // a stalled transfer (a large file GET that never delivers its LAST
  // packet). Recording only; it does not change reassembly behaviour.
  function createRfc76Reassembler() {
    var chunks = [];
    var packetCount = 0;
    var byteCount = 0;
    var lastStatus = null;
    var lastSeq = null;
    var expectNextSeq = null;
    var sequenceGap = null; // { expected, got } for the first gap seen
    return {
      pushPacket: function (packet) {
        var headerByte = packet[0];
        var status = (headerByte >> 1) & 0x03;
        var seq = (headerByte >> 4) & 0x0f;
        var payload = packet.slice(RFC76_HEADER_SIZE);
        packetCount += 1;
        lastStatus = status;
        lastSeq = seq;
        if (expectNextSeq !== null && seq !== expectNextSeq && sequenceGap === null) {
          sequenceGap = { expected: expectNextSeq, got: seq };
        }
        expectNextSeq = (seq + 1) & 0x0f;
        if (status === RFC76_STATUS_ERROR_OR_RESPONSE) {
          var errorCode = (payload[0] | (payload[1] << 8)) & 0xffff;
          return { done: true, error: errorCode, payload: null };
        }
        chunks.push(payload);
        byteCount += payload.length;
        if (status === RFC76_STATUS_LAST) {
          var total = 0;
          for (var i = 0; i < chunks.length; i++) total += chunks[i].length;
          var out = new Uint8Array(total);
          var off = 0;
          for (var j = 0; j < chunks.length; j++) { out.set(chunks[j], off); off += chunks[j].length; }
          return { done: true, error: null, payload: out };
        }
        return { done: false };
      },
      stats: function () {
        return {
          packetCount: packetCount,
          byteCount: byteCount,
          lastStatus: lastStatus,
          lastSeq: lastSeq,
          sequenceGap: sequenceGap
        };
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

  // Shared ACC frame-shape constants -- every Verity Sense config Lane
  // Pulse has seen uses 3 channels (x/y/z) at 16-bit resolution for
  // compressed frames' reference samples. Named here (rather than left as
  // magic numbers inside decodeAccFrame) because the structural frame-
  // boundary walk below needs the exact same values to know how many
  // reference-sample bytes a compressed frame starts with.
  var ACC_COMPRESSED_CHANNELS = 3;
  var ACC_COMPRESSED_RESOLUTION_BITS = 16;
  var ACC_COMPRESSED_REF_BYTE_LEN = Math.ceil(ACC_COMPRESSED_RESOLUTION_BITS / 8);
  var ACC_RAW_BYTE_WIDTHS = { 0: 1, 1: 2, 2: 3 }; // bytes/channel by raw frameType

  // ACC-specific decode, dispatching on frame type + compressed flag.
  // Ported from AccData.kt -- only the paths Lane Pulse needs (types 0-2
  // raw, types 0-1 compressed; that covers every Verity Sense config).
  function decodeAccFrame(envelope, previousTimeStamp, factor, sampleRate) {
    var samples = [];
    var raw;
    if (envelope.isCompressedFrame) {
      if (envelope.frameType === 0) {
        raw = parseDeltaFramesAll(envelope.dataContent, ACC_COMPRESSED_CHANNELS, ACC_COMPRESSED_RESOLUTION_BITS);
        var accFactor = factor * 1000; // arrives in G, convert to milliG
        var ts0 = getTimeStamps(previousTimeStamp, envelope.timeStamp, raw.length, sampleRate);
        for (var i = 0; i < raw.length; i++) {
          samples.push({ timeStamp: ts0[i], x: Math.round(raw[i][0] * accFactor), y: Math.round(raw[i][1] * accFactor), z: Math.round(raw[i][2] * accFactor) });
        }
      } else if (envelope.frameType === 1) {
        raw = parseDeltaFramesAll(envelope.dataContent, ACC_COMPRESSED_CHANNELS, ACC_COMPRESSED_RESOLUTION_BITS);
        var ts1 = getTimeStamps(previousTimeStamp, envelope.timeStamp, raw.length, sampleRate);
        for (var j = 0; j < raw.length; j++) {
          var scale = factor !== 1.0 ? factor : 1;
          samples.push({ timeStamp: ts1[j], x: Math.round(raw[j][0] * scale), y: Math.round(raw[j][1] * scale), z: Math.round(raw[j][2] * scale) });
        }
      } else {
        throw new Error("ACC compressed frame type " + envelope.frameType + " not supported");
      }
    } else {
      var step = ACC_RAW_BYTE_WIDTHS[envelope.frameType];
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

  // Finds the real frame-start offset nearest to expectedOffset, searching
  // only within [searchFrom, searchTo) for a plausible envelope (matching
  // measurementType, valid frameType) via scanForFrameBoundaries. Falls back
  // to expectedOffset itself when nothing plausible is found nearby -- e.g.
  // right at end-of-file, or a frame type this scan can't recognize.
  function findFrameBoundaryNear(fileBytes, searchFrom, searchTo, expectedOffset, measurementType) {
    var candidates = scanForFrameBoundaries(fileBytes, searchFrom, searchTo, measurementType);
    if (!candidates.length) return expectedOffset;
    candidates.sort(function (a, b) { return Math.abs(a.offset - expectedOffset) - Math.abs(b.offset - expectedOffset); });
    return candidates[0].offset;
  }

  // One-shot version of the boundary search: corrects just the frame 0 ->
  // frame 1 gap and reports it as a stride. Kept as a simple, directly
  // testable utility (and still exported for debugging) -- superseded
  // within decodeAccRecordingFile itself by locateFrameOffsets below, which
  // repeats this same empirical search per-frame rather than assuming one
  // gap size holds for an entire file (real-hardware testing found frame
  // sizes drift frame-to-frame in compressed recordings, not just once).
  function determineRealFrameStride(fileBytes, header) {
    var documented = header.dataPayloadSize;
    if (header.dataOffset + documented > fileBytes.length) return documented;
    var envelope0 = parsePmdDataFrameEnvelope(fileBytes.slice(header.dataOffset, header.dataOffset + documented));
    var expectedOffset = header.dataOffset + documented;
    var searchFrom = Math.max(header.dataOffset + 1, expectedOffset - 20);
    var searchTo = expectedOffset + 20;
    var realOffset = findFrameBoundaryNear(fileBytes, searchFrom, searchTo, expectedOffset, envelope0.measurementType);
    return realOffset - header.dataOffset;
  }

  // Walks the frame stream one frame at a time, re-measuring the boundary
  // to the *next* frame after each one rather than trusting a single global
  // stride for the whole file. Real-hardware testing showed this is
  // necessary: compressed ACC frames can each pack a different number of
  // delta-encoded samples, so consecutive frames aren't reliably the same
  // byte length even when frame 0 -> frame 1 happens to match a simple
  // "documented + 2" pattern. Returns an array of frame *start* offsets;
  // the caller derives each frame's byte range from consecutive offsets
  // (and the documented size for the final frame).
  function locateFrameOffsets(fileBytes, header) {
    var documented = header.dataPayloadSize;
    var searchWindow = 60; // generous -- a stray false-positive match needs both the right measurementType byte AND a plausible frameType, so collisions are very unlikely even over a wider window
    var offsets = [];
    var currentOffset = header.dataOffset;
    while (currentOffset + 10 <= fileBytes.length) {
      offsets.push(currentOffset);
      var envelope;
      try {
        envelope = parsePmdDataFrameEnvelope(fileBytes.slice(currentOffset, Math.min(currentOffset + documented, fileBytes.length)));
      } catch (err) {
        break; // not enough bytes left for even one more envelope
      }
      var expectedNext = currentOffset + documented;
      if (expectedNext + 10 > fileBytes.length) break; // no room left for another full frame
      var searchFrom = Math.max(currentOffset + 1, expectedNext - searchWindow);
      var searchTo = expectedNext + searchWindow;
      currentOffset = findFrameBoundaryNear(fileBytes, searchFrom, searchTo, expectedNext, envelope.measurementType);
    }
    return offsets;
  }

  // Does the file look like it has a genuine PMD frame envelope starting at
  // `offset`? Checked after every raw sample / compressed delta block while
  // walking a frame's content (see walkAndDecodeAccFrames below) to find
  // where that frame actually ends -- no fixed search window, so it handles
  // drift of any size, not just a small window around a guessed offset.
  //
  // Matching measurementType + a plausible frameType (<=14) alone isn't a
  // strong enough signal on its own (real sample bytes can coincidentally
  // match ~0.05% of the time) -- adding a timestamp check makes a false
  // positive from random mid-frame data astronomically unlikely: the next
  // frame's 8-byte timestamp must be >= the current frame's, and within a
  // generous 30-second window of it (real ACC frames span well under that
  // even with hundreds of packed samples), while a random 8-byte pattern
  // lands in that narrow a window against the full 64-bit space essentially
  // never.
  var MAX_PLAUSIBLE_INTER_FRAME_NS = 30n * 1000000000n;
  function looksLikeNextEnvelope(fileBytes, offset, expectedMeasurementType, notBeforeTimeStamp) {
    if (offset + 10 > fileBytes.length) return false;
    if (fileBytes[offset] !== expectedMeasurementType) return false;
    var frameType = fileBytes[offset + 9] & 0x7f;
    if (frameType > 14) return false;
    var ts = 0n;
    for (var i = 7; i >= 0; i--) ts = (ts << 8n) | BigInt(fileBytes[offset + 1 + i]);
    if (ts < notBeforeTimeStamp) return false;
    if (ts - notBeforeTimeStamp > MAX_PLAUSIBLE_INTER_FRAME_NS) return false;
    return true;
  }

  // Consumes a raw ACC frame's content one fixed-width sample (x/y/z
  // triple) at a time, stopping the moment what follows looks like a real
  // next envelope. Returns the number of content bytes consumed.
  function consumeRawFrameContent(fileBytes, contentStart, step, measurementType, notBeforeTimeStamp) {
    var sampleByteSize = step * 3;
    var offset = contentStart;
    while (offset + sampleByteSize <= fileBytes.length) {
      var nextOffset = offset + sampleByteSize;
      if (looksLikeNextEnvelope(fileBytes, nextOffset, measurementType, notBeforeTimeStamp)) {
        return nextOffset - contentStart;
      }
      offset = nextOffset;
    }
    return offset - contentStart; // ran out of file -- this is the last frame
  }

  // Consumes a compressed ACC frame's content: a fixed-size reference
  // sample, then delta blocks (each self-describing its own byte length via
  // a [deltaSize][sampleCount] header, per parseDeltaFramesAll) one at a
  // time, stopping the moment what follows looks like a real next envelope.
  // Returns the number of content bytes consumed.
  function consumeCompressedFrameContent(fileBytes, contentStart, channels, refByteLen, measurementType, notBeforeTimeStamp) {
    var offset = contentStart + channels * refByteLen;
    if (looksLikeNextEnvelope(fileBytes, offset, measurementType, notBeforeTimeStamp)) {
      return offset - contentStart; // frame was just the reference sample, no delta blocks
    }
    while (offset + 2 <= fileBytes.length) {
      var deltaSize = fileBytes[offset];
      var sampleCount = fileBytes[offset + 1];
      var byteLength = Math.ceil((sampleCount * deltaSize * channels) / 8);
      var blockEnd = offset + 2 + byteLength;
      if (blockEnd > fileBytes.length) break; // ran out of file mid-block -- take what's left
      if (looksLikeNextEnvelope(fileBytes, blockEnd, measurementType, notBeforeTimeStamp)) {
        return blockEnd - contentStart;
      }
      offset = blockEnd;
    }
    return offset - contentStart; // ran out of file -- this is the last frame
  }

  // Walks the whole frame stream, decoding each frame's content unit-by-
  // unit to find its real boundary (see consumeRawFrameContent /
  // consumeCompressedFrameContent) rather than guessing it from a
  // documented size. This is what decodeAccRecordingFile actually uses --
  // locateFrameOffsets/determineRealFrameStride above are kept as simpler,
  // exported utilities (and still what the debug tooling's diagnostics are
  // built on) but proved insufficient on real hardware: compressed frames'
  // real length can drift by more than any fixed search window handles, and
  // a single mislocated frame corrupts every frame after it.
  function walkAndDecodeAccFrames(fileBytes, header, factor, sampleRate) {
    var offset = header.dataOffset;
    var allSamples = [];
    var previousTimeStamp = 0n;
    var frameIndex = 0;
    while (offset + 10 <= fileBytes.length) {
      var envelope;
      try {
        envelope = parsePmdDataFrameEnvelope(fileBytes.slice(offset, Math.min(offset + 10, fileBytes.length)));
      } catch (err) {
        break; // not enough bytes left for even one more envelope -- done
      }
      var contentStart = offset + 10;
      var contentLength;
      try {
        if (envelope.isCompressedFrame) {
          contentLength = consumeCompressedFrameContent(
            fileBytes, contentStart, ACC_COMPRESSED_CHANNELS, ACC_COMPRESSED_REF_BYTE_LEN,
            envelope.measurementType, envelope.timeStamp
          );
        } else {
          var step = ACC_RAW_BYTE_WIDTHS[envelope.frameType];
          if (!step) throw new Error("ACC raw frame type " + envelope.frameType + " not supported");
          contentLength = consumeRawFrameContent(fileBytes, contentStart, step, envelope.measurementType, envelope.timeStamp);
        }
        envelope.dataContent = fileBytes.slice(contentStart, contentStart + contentLength);
        var samples = decodeAccFrame(envelope, previousTimeStamp, factor, sampleRate);
        previousTimeStamp = envelope.timeStamp;
        allSamples = allSamples.concat(samples);
      } catch (err) {
        var firstBytes = Array.prototype.slice.call(fileBytes.slice(offset, offset + 10))
          .map(function (b) { return ("0" + b.toString(16)).slice(-2); }).join(" ");
        throw new Error(err.message + " [frame " + frameIndex + ", file offset " + offset + ", envelope bytes: " + firstBytes + "]");
      }
      offset = contentStart + contentLength;
      frameIndex += 1;
    }
    return { samples: allSamples, frameCount: frameIndex };
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

    var walked = walkAndDecodeAccFrames(fileBytes, header, factor, sampleRate);

    return { header: header, settings: settings, sampleRate: sampleRate, factor: factor, frameCount: walked.frameCount, samples: walked.samples };
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
  // Total ceiling for one request. Big .REC files stream at only ~13 KB/s
  // over this link, so a genuinely large recording can legitimately take a
  // while -- diagnostics showed one file still actively receiving (589 KB
  // and counting) when a 45s ceiling fired.
  var PSFTP_TIMEOUT_MS = 90000;
  // If the response stream goes silent for this long *after at least one
  // packet has arrived* (or after the request was fully written and nothing
  // ever came back), the transfer has died -- fail fast instead of waiting
  // out the full ceiling. Real hardware: a request issued while the previous
  // file's stream was still draining would get a handful of stray packets
  // and then nothing for ~40s.
  var PSFTP_STALL_MS = 8000;

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
      var framesWritten = 0;
      var lastPacketAt = 0;
      var stallId = null;

      function diagSuffix(reasonWord) {
        var s = reassembler.stats();
        var sinceLastPacket = lastPacketAt ? (Date.now() - lastPacketAt) + "ms ago" : "no packets ever";
        return " (path: " + path + ") [req frames " + framesWritten + "/" + frames.length +
          " sent, resp packets " + s.packetCount + ", bytes " + s.byteCount +
          ", last status " + s.lastStatus + ", last seq " + s.lastSeq +
          ", seq gap " + (s.sequenceGap ? (s.sequenceGap.expected + "->" + s.sequenceGap.got) : "none") +
          ", last packet " + sinceLastPacket + "]";
      }

      var timeoutId = setTimeout(function () {
        if (settled) return;
        settled = true;
        cleanup();
        reject(new Error("PSFTP request timed out after " + PSFTP_TIMEOUT_MS + "ms" + diagSuffix()));
      }, PSFTP_TIMEOUT_MS);

      // Reset on every packet (and armed once the request is fully sent):
      // fires when the stream has been silent long enough to call the
      // transfer dead, well before the full ceiling.
      function armStall() {
        if (settled) return;
        if (stallId) clearTimeout(stallId);
        stallId = setTimeout(function () {
          if (settled) return;
          settled = true;
          cleanup();
          reject(new Error("PSFTP transfer stalled -- no packet for " + PSFTP_STALL_MS + "ms" + diagSuffix()));
        }, PSFTP_STALL_MS);
      }

      function cleanup() {
        clearTimeout(timeoutId);
        if (stallId) clearTimeout(stallId);
        mtuChar.removeEventListener("characteristicvaluechanged", onNotify);
      }

      function onNotify(evt) {
        if (settled) return;
        lastPacketAt = Date.now();
        armStall();
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
          framesWritten = i;
          return sendNext();
        });
      }
      sendNext().then(function () {
        armStall(); // a device that never answers at all still trips the stall timer, not just the ceiling
      }).catch(function (err) {
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

  // Resolve once the channel has been silent (no notification) for quietMs.
  // A timed-out or stalled transfer can leave the device still pushing
  // packets for the previous file; firing the next request into that stream
  // corrupts both. Call this between sequential fetches to let the previous
  // transfer fully drain first. Caps its own wait so a device that just
  // never goes quiet can't hang the caller forever.
  function drainChannel(mtuChar, quietMs, maxWaitMs) {
    quietMs = quietMs || 2500;
    maxWaitMs = maxWaitMs || 20000;
    return new Promise(function (resolve) {
      var quietTimer = null;
      var hardCap = null;
      function finish() {
        if (quietTimer) clearTimeout(quietTimer);
        if (hardCap) clearTimeout(hardCap);
        mtuChar.removeEventListener("characteristicvaluechanged", onAny);
        resolve();
      }
      function onAny() {
        if (quietTimer) clearTimeout(quietTimer);
        quietTimer = setTimeout(finish, quietMs);
      }
      mtuChar.addEventListener("characteristicvaluechanged", onAny);
      quietTimer = setTimeout(finish, quietMs);
      hardCap = setTimeout(finish, maxWaitMs);
    });
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
    findFrameBoundaryNear: findFrameBoundaryNear,
    determineRealFrameStride: determineRealFrameStride,
    locateFrameOffsets: locateFrameOffsets,
    looksLikeNextEnvelope: looksLikeNextEnvelope,
    consumeRawFrameContent: consumeRawFrameContent,
    consumeCompressedFrameContent: consumeCompressedFrameContent,
    walkAndDecodeAccFrames: walkAndDecodeAccFrames,
    parsePmdSettings: parsePmdSettings,
    readFloat32LE: readFloat32LE,
    decodeAccRecordingFile: decodeAccRecordingFile,

    // GATT orchestration (browser-only, untested by the Node suite)
    psftpRequest: psftpRequest,
    preparePsftpChannel: preparePsftpChannel,
    listDirectory: listDirectory,
    getFile: getFile,
    drainChannel: drainChannel,
    findOfflineAccRecordings: findOfflineAccRecordings
  };
});
