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

// stats() -- diagnostic counters for a stalled transfer. Feed the
// multi-frame round trip again but stop one packet short of LAST, then
// check what stats() reports about the incomplete stream.
var reassembler4 = O.createRfc76Reassembler();
for (var g = 0; g < frames.length - 1; g++) reassembler4.pushPacket(frames[g]);
var stalledStats = reassembler4.stats();
assertEqual(stalledStats.packetCount, frames.length - 1, "reassembler.stats: counts packets received before the stall");
assertEqual(stalledStats.sequenceGap, null, "reassembler.stats: no sequence gap on a clean (if incomplete) stream");
assertEqual(stalledStats.lastStatus, 3, "reassembler.stats: last status is MORE (3) while still mid-stream");

// stats() flags a sequence discontinuity (a dropped packet) -- skip frame 1
var reassembler5 = O.createRfc76Reassembler();
reassembler5.pushPacket(frames[0]);
reassembler5.pushPacket(frames[2]); // frame 1 dropped
var gapStats = reassembler5.stats();
assertEqual(gapStats.sequenceGap, { expected: 1, got: 2 }, "reassembler.stats: records the first sequence-number gap (dropped packet)");

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

// getTimeStamps: a non-positive delta between frames used to be fatal
// (threw and aborted the whole file); real hardware testing found it
// happening on otherwise-valid frames deep into files that had already
// decoded dozens of frames cleanly, so it's now tolerated with a fallback
// to nominal per-sample spacing instead of throwing.
var backwardsTs = O.getTimeStamps(2000n, 1500n, 4, 52); // frameTimeStamp (1500) < previousFrameTimeStamp (2000)
assertEqual(backwardsTs.length, 4, "getTimeStamps: a non-positive delta no longer throws -- still returns one timestamp per sample");
assertEqual(backwardsTs[3], 1500n, "getTimeStamps: the last sample still carries the frame's own (real) timestamp even on the fallback path");
var equalTs = O.getTimeStamps(2000n, 2000n, 3, 52); // frameTimeStamp === previousFrameTimeStamp (zero delta)
assertEqual(equalTs.length, 3, "getTimeStamps: a zero delta between frames also falls back rather than throwing");

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
// encodePmdSettingsSelected -- the encode counterpart of parsePmdSettings,
// used to build the REQUEST_MEASUREMENT_START payload when triggering a
// new offline recording. [typeId][count=1][value bytes LE].
// ---------------------------------------------------------------------
assertEqual(
  O.encodePmdSettingsSelected({ SAMPLE_RATE: 52 }),
  [0, 1, 52, 0],
  "encodePmdSettingsSelected: SAMPLE_RATE (2-byte LE)"
);
assertEqual(
  O.encodePmdSettingsSelected({ CHANNELS: 3, RANGE: 8 }),
  [2, 1, 8, 0, 4, 1, 3], // RANGE (typeId 2) before CHANNELS (typeId 4) -- always ascending typeId order, regardless of key order in `selected`
  "encodePmdSettingsSelected: multiple settings encode in ascending typeId order"
);
assertEqual(
  O.encodePmdSettingsSelected({ SAMPLE_RATE: 52, FACTOR: 1.0 }),
  [0, 1, 52, 0], // FACTOR is response-only and must never be sent, even if present in `selected`
  "encodePmdSettingsSelected: silently skips response-only fields (FACTOR)"
);
assertEqual(O.encodePmdSettingsSelected({}), [], "encodePmdSettingsSelected: empty selection encodes to nothing");

// ---------------------------------------------------------------------
// chooseOfflineAccSettings -- picks 52Hz/16-bit/3ch/8-range when the
// device offers them (matching every real recording decoded so far),
// falls back to the highest available value otherwise, and omits a
// setting entirely if the device advertised no options for it at all.
// ---------------------------------------------------------------------
assertEqual(
  O.chooseOfflineAccSettings({ SAMPLE_RATE: [13, 26, 52, 104], RESOLUTION: [16], CHANNELS: [3], RANGE: [2, 4, 8] }),
  { SAMPLE_RATE: 52, RESOLUTION: 16, CHANNELS: 3, RANGE: 8 },
  "chooseOfflineAccSettings: picks the preferred value when the device offers it"
);
assertEqual(
  O.chooseOfflineAccSettings({ SAMPLE_RATE: [13, 26, 104] }),
  { SAMPLE_RATE: 104 },
  "chooseOfflineAccSettings: falls back to the max available value when the preferred one isn't offered"
);
assertEqual(
  O.chooseOfflineAccSettings({ SAMPLE_RATE: [52] }),
  { SAMPLE_RATE: 52 },
  "chooseOfflineAccSettings: omits a setting entirely when the device advertises no options for it"
);

// ---------------------------------------------------------------------
// parsePmdControlPointResponse -- [0]=0xF0 response code, [1]=opcode,
// [2]=measurement type, [3]=status, [4]=more flag (SUCCESS only),
// [5..]=parameters. Mirrors PmdControlPointResponse.kt from the official
// SDK exactly.
// ---------------------------------------------------------------------
var successResponse = O.parsePmdControlPointResponse([0xf0, 2, 2, 0, 0, 10, 20]);
assertEqual(successResponse.statusCode, 0, "parsePmdControlPointResponse: SUCCESS status code");
assertEqual(successResponse.statusName, "SUCCESS", "parsePmdControlPointResponse: SUCCESS status name");
assertEqual(successResponse.more, false, "parsePmdControlPointResponse: more=false when the flag byte is 0");
assertEqual(Array.prototype.slice.call(successResponse.parameters), [10, 20], "parsePmdControlPointResponse: parameters");

var continuedResponse = O.parsePmdControlPointResponse([0xf0, 2, 2, 0, 1, 10, 20]);
assertEqual(continuedResponse.more, true, "parsePmdControlPointResponse: more=true when the flag byte is nonzero");

var errorResponse = O.parsePmdControlPointResponse([0xf0, 2, 2, 6]);
assertEqual(errorResponse.statusName, "ERROR_ALREADY_IN_STATE", "parsePmdControlPointResponse: recognizes a real error status code");
assertEqual(errorResponse.more, false, "parsePmdControlPointResponse: more is always false on a non-SUCCESS status, even with no flag byte present");
assertEqual(Array.prototype.slice.call(errorResponse.parameters), [], "parsePmdControlPointResponse: no parameters on error");

assertThrows(function () { O.parsePmdControlPointResponse([0xf0, 2]); }, "parsePmdControlPointResponse rejects a response shorter than the fixed 4-byte header");

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
// decodeAccRecordingFile end-to-end with differently-drifted frame sizes
// (mirrors the real-hardware bug: frame 0 legitimately carries 3 extra
// content bytes -- one more sample -- than the documented dataPayloadSize
// implies, frame 1 carries 6 extra bytes -- a *different* amount -- and
// frame 2 matches the documented size exactly. A single global stride
// correction handles frame 0->1 but then gets frame 1->2 wrong; only a
// per-frame re-measurement gets all three right.)
// ---------------------------------------------------------------------
function buildDriftingTestFile() {
  var bytes = [0x00].concat([0x2b, 0x4c, 0x7c, 0x3d]).concat([0x01, 0x00, 0x00, 0x00]).concat([0x00, 0x00, 0x00, 0x00]).concat([0x00, 0x00, 0x00, 0x00]);
  var dateStr = "2017-01-03 02:13:37";
  for (var i = 0; i < dateStr.length; i++) bytes.push(dateStr.charCodeAt(i));
  bytes.push(0x00);
  var settings = [0, 1, 52, 0, 5, 1, 0x00, 0x00, 0x80, 0x3f];
  bytes.push(settings.length);
  bytes = bytes.concat(settings);
  bytes.push(0);
  bytes = bytes.concat([16, 0]); // documented dataPayloadSize = 16 (a 2-sample raw frame) -- frames 0 and 1 will actually carry more

  function buildRawFrame(timestampLow, samples) {
    var frame = [2].concat([timestampLow, 0, 0, 0, 0, 0, 0, 0]).concat([0x00]); // raw, frameType 0 (1 byte/channel)
    samples.forEach(function (s) { frame = frame.concat([s[0] & 0xff, s[1] & 0xff, s[2] & 0xff]); });
    return frame;
  }
  bytes = bytes.concat(buildRawFrame(100, [[1, 2, 3], [4, 5, 6], [99, 99, 99]]));               // frame 0: 3 samples (real size 19, +3 over documented)
  bytes = bytes.concat(buildRawFrame(200, [[7, 8, 9], [10, 11, 12], [88, 88, 88], [77, 77, 77]])); // frame 1: 4 samples (real size 22, +6 over documented -- a different drift)
  bytes = bytes.concat(buildRawFrame(300, [[13, 14, 15], [16, 17, 18]]));                        // frame 2: 2 samples (real size 16, matches documented exactly)
  return bytes;
}
var driftingFile = buildDriftingTestFile();
var driftDecoded = O.decodeAccRecordingFile(driftingFile);
assertEqual(driftDecoded.frameCount, 3, "decodeAccRecordingFile: finds all 3 frames despite each carrying a different amount of drift");
assertEqual(driftDecoded.samples.length, 9, "decodeAccRecordingFile: decodes all 9 samples (3+4+2) across differently-drifted frames");
// global sample indices: frame 0 -> 0,1,2 (3 samples); frame 1 -> 3,4,5,6 (4 samples); frame 2 -> 7,8 (2 samples)
assertEqual([driftDecoded.samples[2].x, driftDecoded.samples[2].y, driftDecoded.samples[2].z], [99, 99, 99], "decodeAccRecordingFile: frame 0's extra (undocumented) 3rd sample decodes correctly");
assertEqual([driftDecoded.samples[5].x, driftDecoded.samples[5].y, driftDecoded.samples[5].z], [88, 88, 88], "decodeAccRecordingFile: frame 1's extra (undocumented) 3rd sample decodes correctly");
assertEqual([driftDecoded.samples[6].x, driftDecoded.samples[6].y, driftDecoded.samples[6].z], [77, 77, 77], "decodeAccRecordingFile: frame 1's extra (undocumented) 4th sample decodes correctly");
assertEqual([driftDecoded.samples[7].x, driftDecoded.samples[7].y, driftDecoded.samples[7].z], [13, 14, 15], "decodeAccRecordingFile: frame 2's 1st sample decodes correctly");
assertEqual([driftDecoded.samples[8].x, driftDecoded.samples[8].y, driftDecoded.samples[8].z], [16, 17, 18], "decodeAccRecordingFile: frame 2 (exactly documented size) still decodes correctly after two drifted frames");

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
// locateFrameOffsets -- the real-hardware failure this exists to fix: a
// *single* global stride correction isn't enough, because each frame-to-
// frame gap can drift by a DIFFERENT amount (frame 0->1 drifts +2 over the
// documented size, frame 1->2 drifts +5). A decoder using one fixed
// stride for the whole file gets frame 2 wrong; locateFrameOffsets must
// re-measure the gap after every single frame.
// ---------------------------------------------------------------------
var driftBytes = new Array(60).fill(0xff);
driftBytes[0] = 2;  driftBytes[9] = 0x00;        // frame 0 real start: offset 0  (matches documented)
driftBytes[18] = 2; driftBytes[18 + 9] = 0x01;   // frame 1 real start: offset 18 (documented predicted 16, drift +2)
driftBytes[39] = 2; driftBytes[39 + 9] = 0x02;   // frame 2 real start: offset 39 (documented predicted 34, drift +5)
var driftHeader = { dataOffset: 0, dataPayloadSize: 16 };
var frameOffsets = O.locateFrameOffsets(driftBytes, driftHeader);
assertEqual(frameOffsets, [0, 18, 39], "locateFrameOffsets: follows each frame's real (differently-drifted) boundary, not one fixed stride");

// ---------------------------------------------------------------------
// looksLikeNextEnvelope -- the safety property the structural walk (below)
// depends on: measurementType must match and frameType must be plausible
// (<=14). This is deliberately the EXACT SAME criterion scanForFrameBoundaries
// has used all along (proven reliable at scale: a 669-frame real file
// decoded with zero false positives on nothing else) -- an earlier version
// also required a "plausible" timestamp jump, on the unverified assumption
// that PMD frame timestamps are nanoseconds. That assumption was wrong for
// this hardware and rejected every genuine next-frame candidate, so the
// walk swallowed whole files. The large/backwards-jump cases below lock in
// that this must NOT happen again -- both must be ACCEPTED regardless of
// the timestamp value, since timestamp is no longer part of the criterion.
// ---------------------------------------------------------------------
function buildEnvelopeBytes(measurementType, timeStampNs, frameTypeByte) {
  var out = [measurementType];
  var big = BigInt(timeStampNs);
  for (var i = 0; i < 8; i++) { out.push(Number(big & 0xffn)); big >>= 8n; }
  out.push(frameTypeByte);
  return out;
}
var baseTs = 5000000000n; // 5s, arbitrary
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs + 1000000000n, 0x00), 0, 2, baseTs),
  true, "looksLikeNextEnvelope: accepts a matching type + frameType with a nearby timestamp"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs - 1n, 0x00), 0, 2, baseTs),
  true, "looksLikeNextEnvelope: regression guard -- must NOT reject a timestamp that goes backwards (unit/scale is unverified, so timestamp is not part of the criterion)"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs + 31000000000n, 0x00), 0, 2, baseTs),
  true, "looksLikeNextEnvelope: regression guard -- must NOT reject a huge forward jump either, for the same reason"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(3, baseTs + 1000000000n, 0x00), 0, 2, baseTs),
  false, "looksLikeNextEnvelope: rejects a mismatched measurementType"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs + 1000000000n, 0x7f), 0, 2, baseTs),
  false, "looksLikeNextEnvelope: rejects an out-of-range frameType (>14)"
);
// tightened whitelist: real hardware testing found frameType<=14 alone lets
// through too many false matches within real (not random) sensor content
// once checked at every byte position in an unbounded scan -- only the
// exact raw/compressed type+compression combinations Lane Pulse decodes
// should count as "looks like a real frame".
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs, 0x02), 0, 2, baseTs),
  true, "looksLikeNextEnvelope: accepts raw frameType 2 (a supported raw type)"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs, 0x07), 0, 2, baseTs),
  false, "looksLikeNextEnvelope: rejects raw frameType 7 (in the old <=14 range, but not a supported raw type)"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs, 0x81), 0, 2, baseTs),
  true, "looksLikeNextEnvelope: accepts compressed frameType 1 (a supported compressed type)"
);
assertEqual(
  O.looksLikeNextEnvelope(buildEnvelopeBytes(2, baseTs, 0x82), 0, 2, baseTs),
  false, "looksLikeNextEnvelope: rejects compressed frameType 2 (in the old <=14 range, but not a supported compressed type)"
);

// ---------------------------------------------------------------------
// isCompressedContentLengthValid -- real-hardware testing found requiring
// an EXACT landing rejected every genuine compressed frame boundary (real
// frames apparently carry a few bytes of trailing slack this model doesn't
// fully account for). A small tolerance was added; these lock in that it's
// still a real check, not a rubber stamp -- an overrun is always rejected
// regardless of slack, and going past the tolerance window is rejected too.
//
// content: 6 ref bytes + one delta block, deliberately made bigger than the
// tolerance window (header [deltaSize=4, sampleCount=10] -> byteLength =
// ceil(10*4*3/8) = 15) so the tolerance can only ever skip validating a
// few trailing bytes, never mask the real block going unchecked -- 23
// bytes of real, well-formed content in total.
// ---------------------------------------------------------------------
var validCompressedContent = [0, 0, 0, 0, 0, 0, 4, 10].concat(new Array(15).fill(0));
assertEqual(
  O.isCompressedContentLengthValid(validCompressedContent, 0, 23, 3, 2),
  true, "isCompressedContentLengthValid: accepts an exact landing"
);
assertEqual(
  O.isCompressedContentLengthValid(validCompressedContent.concat(new Array(8).fill(0xff)), 0, 31, 3, 2),
  true, "isCompressedContentLengthValid: accepts landing within the trailing-slack tolerance (8 bytes short) without misreading the padding as another block"
);
assertEqual(
  O.isCompressedContentLengthValid(validCompressedContent.concat(new Array(9).fill(0xff)), 0, 32, 3, 2),
  false, "isCompressedContentLengthValid: rejects landing past the trailing-slack tolerance (9 bytes short)"
);
assertEqual(
  O.isCompressedContentLengthValid(validCompressedContent, 0, 18, 3, 2),
  false, "isCompressedContentLengthValid: rejects a candidate that cuts a real (already in-progress, not-yet-in-slack-zone) block short"
);

// ---------------------------------------------------------------------
// findValidNextFrameStart -- the real-hardware failure this exists to fix:
// looksLikeNextEnvelope's type+frameType match, checked at every byte of
// real frame content, does occasionally find a false positive (real sensor
// data isn't random noise -- certain byte values show up more than a
// uniform 1/256 would suggest). A raw frame's content must always be a
// whole number of fixed-width samples, so a false positive that lands
// off that boundary can be detected and rejected structurally, without
// ever needing to know whether it's "real" some other way.
//
// Frame 0: raw type 0 (1 byte/channel), 4 real samples (12 content bytes).
// Byte 4 of that content (absolute offset 14) is deliberately set to 2
// (matching measurementType) with a valid-looking frameType 9 bytes later
// -- a textbook false positive, and NOT a multiple of 3 bytes from the
// frame's start (14-10=4, 4%3=1). The frame's real boundary is at offset
// 22 (10 + 12), where frame 1's genuine envelope actually starts.
// ---------------------------------------------------------------------
var falsePositiveTestBytes = new Array(40).fill(0xff);
falsePositiveTestBytes[0] = 2; // frame 0 measurementType
for (var fi = 1; fi <= 8; fi++) falsePositiveTestBytes[fi] = 0; // frame 0 timestamp (arbitrary)
falsePositiveTestBytes[9] = 0x00; // frame 0 frameType: raw type 0
var frame0Content = [1, 1, 1, 1, 2, 1, 1, 1, 1, 1, 1, 1]; // index 4 (offset 14) = 2, the false positive
for (var ci = 0; ci < frame0Content.length; ci++) falsePositiveTestBytes[10 + ci] = frame0Content[ci];
falsePositiveTestBytes[22] = 2; // frame 1's REAL measurementType, at the true boundary
for (var fi2 = 23; fi2 <= 30; fi2++) falsePositiveTestBytes[fi2] = 0; // frame 1 timestamp (also covers the false positive's own "frameType" byte at 23 -- 0x00 is valid either way)
falsePositiveTestBytes[31] = 0x00; // frame 1 frameType: raw type 0
var fpEnvelope = { isCompressedFrame: false, frameType: 0, measurementType: 2 };
assertEqual(
  O.findValidNextFrameStart(falsePositiveTestBytes, 10, fpEnvelope),
  22,
  "findValidNextFrameStart: rejects a false-positive match that isn't a whole number of raw samples from the frame start, finds the true boundary instead"
);

// ---------------------------------------------------------------------
// walkAndDecodeAccFrames / decodeAccRecordingFile end-to-end via the
// structural walk -- a raw frame followed by a compressed frame, with the
// header's dataPayloadSize deliberately wrong (5, nowhere near either
// frame's real size) to prove the structural walk doesn't consult it at
// all. This is the real fix for the real-hardware bug: locateFrameOffsets'
// fixed search window couldn't handle drift beyond it (garbage frame types
// 7/13/14 showed up deep into real files); the structural walk has no
// window to exceed since it decodes each frame's actual content directly.
// ---------------------------------------------------------------------
function le8(n) {
  var out = [];
  var big = BigInt(n);
  for (var i = 0; i < 8; i++) { out.push(Number(big & 0xffn)); big >>= 8n; }
  return out;
}
function le16Signed(v) {
  var u = v < 0 ? v + 65536 : v;
  return [u & 0xff, (u >> 8) & 0xff];
}
function buildStructuralTestFile() {
  var bytes = [0x00].concat([0x2b, 0x4c, 0x7c, 0x3d]).concat([0x01, 0, 0, 0]).concat([0, 0, 0, 0]).concat([0, 0, 0, 0]);
  var dateStr = "2017-01-03 02:13:37";
  for (var i = 0; i < dateStr.length; i++) bytes.push(dateStr.charCodeAt(i));
  bytes.push(0x00);
  var settings = [0, 1, 52, 0, 5, 1, 0x00, 0x00, 0x80, 0x3f]; // SAMPLE_RATE=52, FACTOR=1.0
  bytes.push(settings.length);
  bytes = bytes.concat(settings);
  bytes.push(0);
  bytes = bytes.concat([5, 0]); // dataPayloadSize deliberately wrong -- must be ignored entirely

  var ts0 = 1000000000; // 1s
  var frame0 = [2].concat(le8(ts0)).concat([0x00]).concat([1, 2, 3, 4, 5, 6]); // raw type 0, 2 samples

  var ts1 = ts0 + 100000000; // +0.1s, plausible
  var refBytes = le16Signed(10).concat(le16Signed(-5)).concat(le16Signed(0));
  var deltaBlock = packBitsLSBFirst([2, -1, 3], 4);
  var frame1 = [2].concat(le8(ts1)).concat([0x81]).concat(refBytes).concat([4, 1]).concat(deltaBlock); // compressed type 1

  return bytes.concat(frame0).concat(frame1);
}
var structuralFile = buildStructuralTestFile();
var structDecoded = O.decodeAccRecordingFile(structuralFile);
assertEqual(structDecoded.frameCount, 2, "decodeAccRecordingFile (structural walk): finds both frames despite a wildly wrong documented dataPayloadSize");
assertEqual(structDecoded.samples.length, 4, "decodeAccRecordingFile (structural walk): decodes all 4 samples (2 raw + 2 compressed)");
assertEqual([structDecoded.samples[0].x, structDecoded.samples[0].y, structDecoded.samples[0].z], [1, 2, 3], "structural walk: raw frame sample 0");
assertEqual([structDecoded.samples[1].x, structDecoded.samples[1].y, structDecoded.samples[1].z], [4, 5, 6], "structural walk: raw frame sample 1");
assertEqual([structDecoded.samples[2].x, structDecoded.samples[2].y, structDecoded.samples[2].z], [10, -5, 0], "structural walk: compressed frame reference sample");
assertEqual([structDecoded.samples[3].x, structDecoded.samples[3].y, structDecoded.samples[3].z], [12, -6, 3], "structural walk: compressed frame delta-decoded sample");

// ---------------------------------------------------------------------
// detectStrokes -- EXPERIMENTAL stroke-rate estimation (see the big
// comment above its definition in offline-recording.js for the important
// caveat: no real, manually-counted swim recording exists yet to validate
// against). These tests only confirm the peak-detection MECHANICS behave
// as designed against known synthetic signals -- they say nothing about
// real-world accuracy against an actual swimmer.
// ---------------------------------------------------------------------
function buildSineSamples(sampleRateHz, durationSec, freqHz, amplitude, baseline) {
  var n = Math.round(sampleRateHz * durationSec);
  var samples = [];
  for (var i = 0; i < n; i++) {
    var t = i / sampleRateHz;
    samples.push({ x: baseline + amplitude * Math.sin(2 * Math.PI * freqHz * t), y: 0, z: 0 });
  }
  return samples;
}

// a clean 1Hz signal (60 strokes/min) over 10s should count exactly 10
// peaks, evenly spaced ~52 samples apart (one full cycle at 52Hz)
var cleanSignal = buildSineSamples(52, 10, 1.0, 200, 1000);
var cleanResult = O.detectStrokes(cleanSignal, 52);
assertEqual(cleanResult.strokeCount, 10, "detectStrokes: counts exactly 10 peaks for a clean 1Hz signal over 10s");
assertEqual(Math.round(cleanResult.avgStrokeRateSpm), 60, "detectStrokes: reports ~60 strokes/min for a clean 1Hz signal");

// a perfectly flat signal (no variation at all) has no peaks to find
var flatSignal = [];
for (var fi = 0; fi < 200; fi++) flatSignal.push({ x: 1000, y: 0, z: 0 });
assertEqual(O.detectStrokes(flatSignal, 52).strokeCount, 0, "detectStrokes: a flat signal produces zero strokes");

// two sharp spikes only 5 samples apart (well under the ~18-sample/0.35s
// refractory period at 52Hz) must be counted as ONE stroke, not two --
// this is what keeps one stroke's ripple from being double-counted
var closeSpikes = [];
for (var ci = 0; ci < 100; ci++) closeSpikes.push({ x: 1000, y: 0, z: 0 });
closeSpikes[30] = { x: 1400, y: 0, z: 0 };
closeSpikes[35] = { x: 1420, y: 0, z: 0 };
assertEqual(O.detectStrokes(closeSpikes, 52).strokeCount, 1, "detectStrokes: refractory period merges two close spikes into one stroke");

// a strong 1Hz signal with a small high-frequency wiggle riding on top
// (8Hz, amplitude 5 vs the main signal's 200) must count only the real
// strokes, not the sub-threshold wiggle
var mixedSignal = [];
var mixedN = 52 * 6;
for (var mi = 0; mi < mixedN; mi++) {
  var mt = mi / 52;
  var big = 200 * Math.sin(2 * Math.PI * 1.0 * mt);
  var tiny = 5 * Math.sin(2 * Math.PI * 8.0 * mt);
  mixedSignal.push({ x: 1000 + big + tiny, y: 0, z: 0 });
}
assertEqual(O.detectStrokes(mixedSignal, 52).strokeCount, 6, "detectStrokes: ignores a sub-threshold high-frequency wiggle, counts only the real 1Hz strokes (6 over 6s)");

// degenerate inputs shouldn't throw
assertEqual(O.detectStrokes([], 52), { strokeCount: 0, avgStrokeRateSpm: 0, peakIndices: [] }, "detectStrokes: empty samples array returns a zero result, doesn't throw");
assertEqual(O.detectStrokes(cleanSignal, 0), { strokeCount: 0, avgStrokeRateSpm: 0, peakIndices: [] }, "detectStrokes: zero/missing sample rate returns a zero result, doesn't throw");

// ---------------------------------------------------------------------
console.log("");
if (failures > 0) {
  console.log(failures + " FAILURE(S)");
  process.exit(1);
} else {
  console.log("ALL TESTS PASSED");
}
