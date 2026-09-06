"use strict";
/* Durable single-file writes.

   The normal path is write-to-tmp then rename, so a crash mid-write can never leave a
   half-written file behind. That breaks in one specific place: when the target is a
   *single-file* Docker bind mount (compose `- ./persistent/content.json:/app/content.json`),
   the kernel refuses to let rename replace the mount point and throws EBUSY. Other
   platforms report the same situation as EXDEV or, on Windows, EPERM.

   In that case the only way to update the file is to write through the mount in place,
   which also keeps the inode the host is bound to. We give up crash-atomicity there
   because the mount leaves us no choice, but the .tmp copy is written first and removed
   only after the real write lands, so a failed write still leaves a recoverable copy. */
const fs = require("fs");

const MOUNT_LOCKED = new Set(["EBUSY", "EXDEV", "EPERM"]);

function writeFileAtomic(file, contents, opts) {
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, contents, opts);
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    if (!e || !MOUNT_LOCKED.has(e.code)) throw e;
    fs.writeFileSync(file, contents, opts);
    try { fs.unlinkSync(tmp); } catch (_) { /* the copy is disposable once the real write landed */ }
  }
}

module.exports = { writeFileAtomic };
