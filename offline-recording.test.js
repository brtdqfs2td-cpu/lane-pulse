"use strict";
// Run with: node offline-recording.test.js
// Pure-logic tests -- no browser, no BLE, no build step.

var O = require("./offline-recording.js");
var failures = 0;
function assertEqual(actual, expected, label) {
  var a = JSON.stringify(actual, function (k, v) { return typeof v === "bigint" ? v.toString() + "n" : v; });
  var e = JSON.stringify(expected, function (k, v) { return typeof v === "bigint" ? v.toString() + "n" : v; });
  if (a !== e) {
    failures += 1;
    console.log("FAIL: " + label);
    console.log("  expected: " + e);
    console.log("  actual:   " + a);
  } else {
    console.log("ok - " + label);
  }
}

// ---------------------------------------------------------------------
// Varint
// ---------------------------------------------------------------------
assertEqual(O.encodeVarint(0), [0x00], "varint encode 0");
assertEqual(O.encodeVarint(127), [0x7f], "varint encode 127 (1 byte boundary)");
assertEqual(O.encodeVarint(128), [0x80, 0x01], "varint encode 128 (2 byte boundary)");
assertEqual(O.encodeVarint(300), [0xac, 0x02], "varint encode 300");
assertEqual(O.readVarint([0xac, 0x02], 0).value, 300, "varint decode 300 round-trip");
assertEqual(O.readVarint([0x80, 0x01, 0xff], 0), { value: 128, offset: 2 }, "varint decode stops at correct offset");

// ---------------------------------------------------------------------
// PbPFtpOperation encoding -- hand-verified against the proto2 wire format:
// field 1 (command, varint): tag = (1<<3)|0 = 0x08
// field 2 (path, length-delimited): tag = (2<<3)|2 = 0x12
// ---------------------------------------------------------------------
var opBytes = Array.prototype.slice.call(O.encodePbPFtpOperation(O.PFTP_COMMAND.GET, "/U/"));
assertEqual(opBytes, [0x08, 0x00, 0x12, 0x03, 0x2f, 0x55, 0x2f], "encodePbPFtpOperation(GET, \"/U/\")");
// 0x08 0x00 = command field, GET(0)
// 0x12 0x03 = path field, length 3
// 0x2f 0x55 0x2f = "/U/" in ASCII

// ---------------------------------------------------------------------
// PbPFtpDirectory / PbPFtpEntry decode -- hand-encode a directory with one
// entry {name: "ACC001.REC", size: 4096} and confirm it decodes correctly.
// ---------------------------------------------------------------------
function encodeTestEntry(name, size) {
  var nameBytes = Array.prototype.slice.call(new TextEncoder().encode(name));
  var entryFields = [0x0a, nameBytes.length].concat(nameBytes) // field1 string, tag=(1<<3)|2=0x0a
    .concat([0x10]).concat(O.encodeVarint(size));               // field2 varint,  tag=(2<<3)|0=0x10
  return entryFields;
}
var entry1 = encodeTestEntry("ACC001.REC", 4096);
var dirBytes = [0x0a, entry1.length].concat(entry1); // PbPFtpDirectory field1 (entries), tag=(1<<3)|2=0x0a
assertEqual(O.decodePbPFtpDirectory(dirBytes), [{ name: "ACC001.REC", size: 4096 }], "decodePbPFtpDirectory single entry");

var entry2 = encodeTestEntry("HR001.REC", 512);
var dirBytes2 = [0x0a, entry1.length].concat(entry1).concat([0x0a, entry2.length]).concat(entry2);
assertEqual(
  O.decodePbPFtpDirectory(dirBytes2),
  [{ name: "ACC001.REC", size: 4096 }, { name: "HR001.REC", size: 512 }],
  "decodePbPFtpDirectory two entries"
);

// ---------------------------------------------------------------------
// RFC76 frame build + reassemble round trip
// ---------------------------------------------------------------------
var message = [];
for (var i = 0; i < 50; i++) message.push(i);
var frames = O.buildRfc76Frames(message, 20); // small MTU forces multiple frames
console.log((frames.length > 1 ? "ok" : "FAIL") + " - buildRfc76Frames splits into multiple packets for small MTU (" + frames.length + " frames)");
if (frames.length <= 1) failures += 1;

var reassembler = O.createRfc76Reassembler();
var result;
for (var f = 0; f < frames.length; f++) {
  result = reassembler.pushPacket(frames[f]);
}
assertEqual(result.done, true, "RFC76 reassembler reports done after LAST packet");
assertEqual(Array.prototype.slice.call(result.payload), message, "RFC76 reassembled payload matches original message");

// single-frame (fits in one MTU) round trip
var smallMsg = [1, 2, 3];
var smallFrames = O.buildRfc76Frames(smallMsg, 200);
assertEqual(smallFrames.length, 1, "buildRfc76Frames single frame when message fits in MTU");
var reassembler2 = O.createRfc76Reassembler();
var result2 = reassembler2.pushPacket(smallFrames[0]);
assertEqual(result2.done, true, "single-frame reassembly done immediately");
assertEqual(Array.prototype.slice.call(result2.payload), smallMsg, "single-frame payload matches");

// error response: status bits = 0, payload = 2-byte LE error code
var errorPacket = [0x00, 103, 0x00]; // status=0 (ERROR_OR_RESPONSE), error code 103 = NO_SUCH_FILE_OR_DIRECTORY
var reassembler3 = O.createRfc76Reassembler();
var errResult = reassembler3.pushPacket(errorPacket);
assertEqual(errResult, { done: true, error: 103, payload: null }, "RFC76 error packet decodes error code 103");

// ---------------------------------------------------------------------
// Delta-frame decompression -- hand-crafted per the documented algorithm:
// 3 channels, 8-bit resolution (1 byte/channel signed ref samples),
// ref = [10, -5, 0], then one block: deltaSize=4 bits, sampleCount=1,
// deltas packed LSB-first per channel: [+2, -1, +3]
// ---------------------------------------------------------------------
// ref samples: 3 signed bytes
var deltaTestBytes = [10, (256 - 5), 0]; // 10, -5 (as unsigned byte 251), 0
// one delta block: deltaSize=4, sampleCount=1
// deltas: +2 = 0b0010, -1 (4-bit two's complement) = 0b1111, +3 = 0b0011
// bit-packed LSB-first across channels in order: ch0(4 bits) ch1(4 bits) ch2(4 bits) = 12 bits = 2 bytes (pad to 16 bits)
// byte0 bits0-7: ch0(0010) then ch1 bits0-3 (1111) => bits: 0,1,0,0, 1,1,1,1 (LSB first) -> value = 0b11110100 = 0xF4
// Actually let's just build via the same bit-packing convention (LSB-first overall stream) rather than hand-deriving hex,
// to avoid a transcription mistake -- build the bitstream explicitly:
function packBitsLSBFirst(values, bitsEach) {
  var bits = [];
  for (var vi = 0; vi < values.length; vi++) {
    var v = values[vi];
    if (v < 0) v = v + (1 << bitsEach); // two's complement within bitsEach
    for (var b = 0; b < bitsEach; b++) bits.push((v >> b) & 1);
  }
  while (bits.length % 8 !== 0) bits.push(0);
  var bytes = [];
  for (var byteI = 0; byteI < bits.length; byteI += 8) {
    var byteVal = 0;
    for (var bitI = 0; bitI < 8; bitI++) byteVal |= (bits[byteI + bitI] << bitI);
    bytes.push(byteVal);
  }
  return bytes;
}
var deltaBlockBytes = packBitsLSBFirst([2, -1, 3], 4);
var fullDeltaTest = deltaTestBytes.concat([4, 1]).concat(deltaBlockBytes);
var decoded = O.parseDeltaFramesAll(fullDeltaTest, 3, 8);
assertEqual(decoded, [[10, -5, 0], [12, -6, 3]], "parseDeltaFramesAll: ref sample + one delta block");

// two delta samples in one block, to confirm cumulative accumulation across samples
var deltaBlockBytes2 = packBitsLSBFirst([1, 1, 1, -1, -1, -1], 4); // two samples of [+1,+1,+1] and [-1,-1,-1]
var fullDeltaTest2 = deltaTestBytes.concat([4, 2]).concat(deltaBlockBytes2);
var decoded2 = O.parseDeltaFramesAll(fullDeltaTest2, 3, 8);
assertEqual(decoded2, [[10, -5, 0], [11, -4, 1], [10, -5, 0]], "parseDeltaFramesAll: two accumulating delta samples");

// ---------------------------------------------------------------------
// PMD data frame envelope parse
// ---------------------------------------------------------------------
// byte0 = measurementType (2 = ACC), bytes1-8 = timestamp (LE uint64) = 1000,
// byte9 = frameType|compressed bit: raw type 0 -> 0x00
var envelopeBytes = [2, 232, 3, 0, 0, 0, 0, 0, 0, 0x00].concat([5, 0, 0, 250, 255, 0]); // 3 raw type-0 (1 byte/ch) samples: [5,0,0] and... wait sizing
// (dataContent must be a multiple of 3 bytes for type 0 -- use exactly 2 samples = 6 bytes)
var envelopeBytes2 = [2, 232, 3, 0, 0, 0, 0, 0, 0, 0x00, 5, 0, 0, 250, 10, 20];
var envelope = O.parsePmdDataFrameEnvelope(envelopeBytes2);
assertEqual(envelope.measurementType, 2, "PMD envelope measurementType");
assertEqual(envelope.timeStamp, 1000n, "PMD envelope timeStamp (1000ns)");
assertEqual(envelope.isCompressedFrame, false, "PMD envelope not compressed");
assertEqual(envelope.frameType, 0, "PMD envelope frameType 0");
assertEqual(Array.prototype.slice.call(envelope.dataContent), [5, 0, 0, 250, 10, 20], "PMD envelope dataContent");

// full ACC raw type-0 decode: 2 samples, [5,0,0] and [-6,10,20] (250 as signed byte = -6)
var accSamples = O.decodeAccFrame(envelope, 0n, 1.0, 52);
assertEqual(accSamples.length, 2, "decodeAccFrame produces 2 samples");
assertEqual([accSamples[0].x, accSamples[0].y, accSamples[0].z], [5, 0, 0], "decodeAccFrame sample 0 x/y/z");
assertEqual([accSamples[1].x, accSamples[1].y, accSamples[1].z], [-6, 10, 20], "decodeAccFrame sample 1 x/y/z (signed byte -6)");
assertEqual(accSamples[1].timeStamp, 1000n, "decodeAccFrame last sample carries the frame's own timestamp");

// ---------------------------------------------------------------------
// File name -> measurement type mapping
// ---------------------------------------------------------------------
assertEqual(O.measurementTypeFromFileName("ACC001.REC"), "ACC", "measurementTypeFromFileName ACC001.REC");
assertEqual(O.measurementTypeFromFileName("HR014.REC"), "HR", "measurementTypeFromFileName HR014.REC");
assertEqual(O.measurementTypeFromFileName("SKINTEMP002.REC"), "SKINTEMP", "measurementTypeFromFileName SKINTEMP002.REC");

// ---------------------------------------------------------------------
// .REC file metadata header -- real test vector: the first 32 bytes of an
// actual ACC.REC file pulled off a Verity Sense (from
// /U/0/20170103/R/021337/ACC.REC via the coach.html debug button).
// Only covers up through the start-time string (32 bytes isn't enough to
// reach the settings/dataOffset fields), so this checks the magic number
// and security byte directly rather than calling the full parser.
// ---------------------------------------------------------------------
var realFilePrefix = [
  0x00, 0x2b, 0x4c, 0x7c, 0x3d, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xba, 0xab, 0xbe,
  0x53, 0x32, 0x30, 0x31, 0x37, 0x2d, 0x30, 0x31, 0x2d, 0x30, 0x33, 0x20, 0x30, 0x32, 0x3a, 0x31
];
assertEqual(realFilePrefix[0], 0x00, "real file: security strategy byte is NONE (0x00)");
var realMagic = (realFilePrefix[1] | (realFilePrefix[2] << 8) | (realFilePrefix[3] << 16) | (realFilePrefix[4] << 24)) >>> 0;
assertEqual(realMagic, O.OFFLINE_HEADER_MAGIC, "real file: magic number at byte offset 1 matches OFFLINE_HEADER_MAGIC exactly");
var realDateTimeChars = realFilePrefix.slice(17, 32).map(function (b) { return String.fromCharCode(b); }).join("");
assertEqual(realDateTimeChars, "2017-01-03 02:1", "real file: readable date-time text starts exactly at byte offset 17");

// Full hand-crafted header (security=NONE, real magic, a short start-time
// string, a 3-byte settings blob, empty security-info, 2-byte payload size)
// to verify parseOfflineRecordingHeader end-to-end, including dataOffset.
function buildTestHeader() {
  var bytes = [0x00]; // security = NONE
  // magic (LE) + version(1) + free(0) + eswHash(0)
  bytes = bytes.concat([0x2b, 0x4c, 0x7c, 0x3d]); // magic
  bytes = bytes.concat([0x01, 0x00, 0x00, 0x00]); // version = 1
  bytes = bytes.concat([0x00, 0x00, 0x00, 0x00]); // free = 0
  bytes = bytes.concat([0x00, 0x00, 0x00, 0x00]); // eswHash = 0
  var dateStr = "2017-01-03 02:13:37"; // 19 chars -- the field is a fixed 20 bytes, null-padded
  for (var i = 0; i < dateStr.length; i++) bytes.push(dateStr.charCodeAt(i));
  bytes.push(0x00); // null pad to fill the 20-byte field
  bytes.push(3); bytes = bytes.concat([0xaa, 0xbb, 0xcc]); // settings: length 3, 3 bytes payload
  bytes.push(0); // security info length 0
  bytes = bytes.concat([0x10, 0x00]); // dataPayloadSize = 16
  bytes = bytes.concat([0xde, 0xad, 0xbe, 0xef]); // simulated start of actual frame data
  return bytes;
}
var testHeader = buildTestHeader();
var parsed = O.parseOfflineRecordingHeader(testHeader);
assertEqual(parsed.securityStrategy, 0, "parseOfflineRecordingHeader: securityStrategy");
assertEqual(parsed.magic, O.OFFLINE_HEADER_MAGIC, "parseOfflineRecordingHeader: magic");
assertEqual(parsed.version, 1, "parseOfflineRecordingHeader: version");
assertEqual(parsed.startTimeRaw, "2017-01-03 02:13:37", "parseOfflineRecordingHeader: startTimeRaw");
// 1(security) + 16(header) + 20(datetime) + 1(settingsLen) + 3(settings) + 1(secInfoLen) + 2(payloadSize) = 44
assertEqual(parsed.dataOffset, 44, "parseOfflineRecordingHeader: dataOffset lands exactly after the fixed+variable sections");
assertEqual(Array.prototype.slice.call(testHeader, parsed.dataOffset), [0xde, 0xad, 0xbe, 0xef], "parseOfflineRecordingHeader: dataOffset correctly points at the simulated frame data");
assertEqual(parsed.dataPayloadSize, 16, "parseOfflineRecordingHeader: dataPayloadSize (fixed per-frame byte size)");

// ---------------------------------------------------------------------
// splitFrameStream: frames are simply fixed-size chunks with no other
// delimiter (confirmed from parseData's slicing loop in
// OfflineRecordingData.kt) -- verify with 3 frames of 4 bytes each.
// ---------------------------------------------------------------------
var multiFrameFile = [0xff, 0xff].concat([1, 2, 3, 4]).concat([5, 6, 7, 8]).concat([9, 10, 11, 12]);
var multiFrameHeader = { dataOffset: 2, dataPayloadSize: 4 };
var splitFrames = O.splitFrameStream(multiFrameFile, multiFrameHeader);
assertEqual(splitFrames.length, 3, "splitFrameStream: splits into 3 frames");
assertEqual(Array.prototype.slice.call(splitFrames[0]), [1, 2, 3, 4], "splitFrameStream: frame 0");
assertEqual(Array.prototype.slice.call(splitFrames[1]), [5, 6, 7, 8], "splitFrameStream: frame 1");
assertEqual(Array.prototype.slice.call(splitFrames[2]), [9, 10, 11, 12], "splitFrameStream: frame 2");

// trailing partial bytes (not a full frame) are dropped, not returned malformed
var withTrailingPartial = [0xff, 0xff].concat([1, 2, 3, 4]).concat([5, 6]); // only 2 of 4 bytes for a 2nd frame
var partialFrames = O.splitFrameStream(withTrailingPartial, { dataOffset: 2, dataPayloadSize: 4 });
assertEqual(partialFrames.length, 1, "splitFrameStream: drops a trailing incomplete frame rather than returning a short one");

// strideOverride -- frames are packetSize=4 bytes but really spaced 5 bytes
// apart (1 padding byte between each), as happens when the documented
// dataPayloadSize doesn't match the real on-disk gap between frames.
var strideFile = [0xff, 0xff]
  .concat([1, 2, 3, 4]).concat([0xee])
  .concat([5, 6, 7, 8]).concat([0xee])
  .concat([9, 10, 11, 12]);
var strideFrames = O.splitFrameStream(strideFile, { dataOffset: 2, dataPayloadSize: 4 }, 5);
assertEqual(strideFrames.length, 3, "splitFrameStream: strideOverride still finds 3 frames");
assertEqual(Array.prototype.slice.call(strideFrames[0]), [1, 2, 3, 4], "splitFrameStream: strideOverride frame 0");
assertEqual(Array.prototype.slice.call(strideFrames[1]), [5, 6, 7, 8], "splitFrameStream: strideOverride frame 1 (skips the padding byte)");
assertEqual(Array.prototype.slice.call(strideFrames[2]), [9, 10, 11, 12], "splitFrameStream: strideOverride frame 2 (skips the padding byte)");

function assertThrows(fn, label) {
  try {
    fn();
    failures += 1;
    console.log("FAIL: " + label + " (expected an exception, got none)");
  } catch (e) {
    console.log("ok - " + label);
  }
}
var wrongMagicHeader = testHeader.slice();
wrongMagicHeader[1] = 0xff; // corrupt the magic
assertThrows(function () { O.parseOfflineRecordingHeader(wrongMagicHeader); }, "parseOfflineRecordingHeader rejects a wrong magic number");

var encryptedHeader = testHeader.slice();
encryptedHeader[0] = 0x02; // SecurityStrategy.AES128
assertThrows(function () { O.parseOfflineRecordingHeader(encryptedHeader); }, "parseOfflineRecordingHeader rejects a non-NONE security strategy");

// ---------------------------------------------------------------------
// readFloat32LE -- 1.0 as IEEE754 is the well-known bit pattern 0x3F800000
// ---------------------------------------------------------------------
assertEqual(O.readFloat32LE([0x00, 0x00, 0x80, 0x3f], 0), 1, "readFloat32LE decodes 1.0 correctly");
assertEqual(O.readFloat32LE([0x00, 0x00, 0x00, 0x00], 0), 0, "readFloat32LE decodes 0.0 correctly");

// ---------------------------------------------------------------------
// parsePmdSettings -- TLV format: [typeId][count][count x fieldSize bytes]
// SAMPLE_RATE=52 (type 0, 2 bytes), CHANNELS=3 (type 4, 1 byte),
// FACTOR=1.0 (type 5, 4 bytes, IEEE754 bits)
// ---------------------------------------------------------------------
var settingsBytes = [
  0, 1, 52, 0,        // SAMPLE_RATE, count 1, value 52 (LE uint16)
  4, 1, 3,            // CHANNELS, count 1, value 3
  5, 1, 0x00, 0x00, 0x80, 0x3f // FACTOR, count 1, 1.0 as float bits
];
var parsedSettings = O.parsePmdSettings(settingsBytes);
assertEqual(parsedSettings.SAMPLE_RATE, [52], "parsePmdSettings: SAMPLE_RATE");
assertEqual(parsedSettings.CHANNELS, [3], "parsePmdSettings: CHANNELS");
assertEqual(parsedSettings.FACTOR, [1], "parsePmdSettings: FACTOR (float bits decoded correctly)");
assertEqual(O.parsePmdSettings([]), {}, "parsePmdSettings: empty input returns empty settings");
assertThrows(function () { O.parsePmdSettings([99, 1, 0]); }, "parsePmdSettings rejects an unknown setting type ID");

// ---------------------------------------------------------------------
// decodeAccRecordingFile -- full synthetic file: header + settings
// (SAMPLE_RATE=52, FACTOR=1.0) + two raw TYPE_0 ACC frames (2 samples
// each, 1 byte/channel, 3 channels -> 6 bytes dataContent -> 16-byte
// frames including the 10-byte envelope).
// ---------------------------------------------------------------------
function buildFullTestFile(settingsBytes) {
  var bytes = [0x00]; // security = NONE
  bytes = bytes.concat([0x2b, 0x4c, 0x7c, 0x3d]); // magic
  bytes = bytes.concat([0x01, 0x00, 0x00, 0x00]); // version
  bytes = bytes.concat([0x00, 0x00, 0x00, 0x00]); // free
  bytes = bytes.concat([0x00, 0x00, 0x00, 0x00]); // eswHash
  var dateStr = "2017-01-03 02:13:37";
  for (var i = 0; i < dateStr.length; i++) bytes.push(dateStr.charCodeAt(i));
  bytes.push(0x00); // null pad to 20 bytes

  var settings = settingsBytes || [0, 1, 52, 0, 5, 1, 0x00, 0x00, 0x80, 0x3f]; // default: SAMPLE_RATE=52, FACTOR=1.0
  bytes.push(settings.length);
  bytes = bytes.concat(settings);
  bytes.push(0); // security info length 0
  bytes = bytes.concat([16, 0]); // dataPayloadSize = 16 (10-byte envelope + 6-byte dataContent)

  function buildFrame(timestampLow, x1, y1, z1, x2, y2, z2) {
    var frame = [2]; // measurementType (unused by decode, arbitrary)
    // 8-byte LE timestamp -- keep it small and only vary the low byte for this test
    frame = frame.concat([timestampLow, 0, 0, 0, 0, 0, 0, 0]);
    frame.push(0x00); // frameType 0, not compressed
    frame = frame.concat([x1 & 0xff, y1 & 0xff, z1 & 0xff, x2 & 0xff, y2 & 0xff, z2 & 0xff]);
    return frame;
  }
  bytes = bytes.concat(buildFrame(100, 1, 2, 3, 4, 5, 6));
  bytes = bytes.concat(buildFrame(200, 7, 8, 9, 10, 11, 12));
  return bytes;
}

var fullFile = buildFullTestFile();
var decoded = O.decodeAccRecordingFile(fullFile);
assertEqual(decoded.sampleRate, 52, "decodeAccRecordingFile: sampleRate read from settings");
assertEqual(decoded.factor, 1, "decodeAccRecordingFile: factor read from settings");
assertEqual(decoded.frameCount, 2, "decodeAccRecordingFile: frameCount");
assertEqual(decoded.samples.length, 4, "decodeAccRecordingFile: total samples across both frames");
assertEqual([decoded.samples[0].x, decoded.samples[0].y, decoded.samples[0].z], [1, 2, 3], "decodeAccRecordingFile: sample 0");
assertEqual([decoded.samples[1].x, decoded.samples[1].y, decoded.samples[1].z], [4, 5, 6], "decodeAccRecordingFile: sample 1");
assertEqual([decoded.samples[2].x, decoded.samples[2].y, decoded.samples[2].z], [7, 8, 9], "decodeAccRecordingFile: sample 2 (2nd frame)");
assertEqual([decoded.samples[3].x, decoded.samples[3].y, decoded.samples[3].z], [10, 11, 12], "decodeAccRecordingFile: sample 3 (2nd frame)");

// derived-measurement recordings must be explicitly rejected, not silently mis-decoded
var derivedSettings = [7, 1, 0]; // DERIVED_MEASUREMENT_METHOD=[0]
var derivedFile = buildFullTestFile(derivedSettings);
assertThrows(function () { O.decodeAccRecordingFile(derivedFile); }, "decodeAccRecordingFile rejects a derived-measurement recording");

// ---------------------------------------------------------------------
// scanForFrameBoundaries -- a real envelope at offset 5 (measurementType=2),
// noise everywhere else, one false-positive-shaped decoy at offset 20 with
// the wrong measurementType (must NOT match).
// ---------------------------------------------------------------------
var scanBytes = new Array(40).fill(0xff);
scanBytes[5] = 2; scanBytes[5 + 9] = 0x81; // valid: type=2, frameType byte 0x81 -> compressed, type 1
scanBytes[20] = 3; scanBytes[20 + 9] = 0x81; // wrong measurementType, must be excluded
var scanResults = O.scanForFrameBoundaries(scanBytes, 0, 40, 2);
assertEqual(scanResults.length, 1, "scanForFrameBoundaries: finds exactly the one matching-type candidate");
assertEqual(scanResults[0], { offset: 5, frameType: 1, compressed: true }, "scanForFrameBoundaries: candidate details are correct");

// ---------------------------------------------------------------------
// determineRealFrameStride -- documented dataPayloadSize says frame 1
// should start at offset 16, but the real (empirically-scanned) frame 1
// envelope actually starts at offset 18. This mirrors the real-hardware
// bug found via the "Scan for frame boundary" debug tool (documented=277,
// real delta=279).
// ---------------------------------------------------------------------
var strideBytes = new Array(50).fill(0xff);
strideBytes[0] = 2;  // frame 0 envelope: measurementType = 2
strideBytes[9] = 0x00; // frame 0: frameType 0, not compressed
strideBytes[18] = 2;  // frame 1's REAL envelope starts at 18, not the documented 16
strideBytes[18 + 9] = 0x01; // frame 1: frameType 1, not compressed
var strideHeader = { dataOffset: 0, dataPayloadSize: 16 };
var realStride = O.determineRealFrameStride(strideBytes, strideHeader);
assertEqual(realStride, 18, "determineRealFrameStride: finds the true 18-byte gap instead of trusting the documented 16");

// when no plausible candidate exists nearby, fall back to the documented value
var noStrideBytes = new Array(50).fill(0xff);
noStrideBytes[0] = 2;
noStrideBytes[9] = 0x00;
// (no second envelope anywhere in the scan window)
var fallbackStride = O.determineRealFrameStride(noStrideBytes, strideHeader);
assertEqual(fallbackStride, 16, "determineRealFrameStride: falls back to the documented dataPayloadSize when no candidate is found");

// ---------------------------------------------------------------------
console.log("");
if (failures > 0) {
  console.log(failures + " FAILURE(S)");
  process.exit(1);
} else {
  console.log("ALL TESTS PASSED");
}
