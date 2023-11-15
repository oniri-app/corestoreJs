const RAF = require("random-access-file");

function defaultStorage(storage, opts = {}) {
  if (typeof storage !== "string") {
    if (!isRandomAccessClass(storage)) return storage;
    const Cls = storage; // just to satisfy standard...
    return (name) => new Cls(name);
  }

  const directory = storage;
  const toLock = opts.unlocked ? null : opts.lock || "oplog";
  const pool =
    opts.pool || (opts.poolSize ? RAF.createPool(opts.poolSize) : null);
  const rmdir = !!opts.rmdir;
  const writable = opts.writable !== false;

  return createFile;

  function createFile(name) {
    const lock = toLock === null ? false : isFile(name, toLock);
    const sparse =
      isFile(name, "data") || isFile(name, "bitfield") || isFile(name, "tree");
    return new RAF(name, {
      directory,
      lock,
      sparse,
      pool: lock ? null : pool,
      rmdir,
      writable,
    });
  }

  function isFile(name, n) {
    return name === n || name.endsWith("/" + n);
  }
}

module.exports = defaultStorage;
