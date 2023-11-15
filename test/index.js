const test = require("brittle");
const Corestore = require("../dist/index.js");
const RAM = require("random-access-memory");
const util = require("util");
const fs = require("fs");
const defaultStorage = require("./utils/defaultStorage.js");

const { pipeline } = require("streamx");

test("basic", function (t) {
  t.is(typeof Corestore, "function");
});

test("test corestore with Random access File", async function (t) {
  const path = "./testStore";
  const store1 = new Corestore(path, { storagefn: defaultStorage });
  await store1.ready();
  await store1.close();
  t.ok(fs.existsSync(path));
  fs.rmSync(path, { recursive: true, force: true });
});

test("test replication", async function (t) {
  const store1 = new Corestore(RAM);
  const store2 = new Corestore(RAM);

  await store1.ready();
  await store2.ready();

  const core1 = store1.get({ name: "core-1" });
  const core2 = store1.get({ name: "core-2" });
  await core1.ready();
  await core2.ready();

  await core1.append("hello");
  await core2.append("world");

  const r1 = await core1.get(0);
  const r2 = await core2.get(0);

  t.is("hello", new util.TextDecoder().decode(r1));
  t.is("world", new util.TextDecoder().decode(r2));

  const core3 = store2.get({ key: core1.key });
  const core4 = store2.get({ key: core2.key });

  await core3.ready();
  await core4.ready();

  const s1 = store1.replicate(true);
  const s2 = store2.replicate(false);

  pipeline(s1, s2, s1, (e) => {
    //console.log("error", e);
  });

  await core3.download();

  const r3 = await core3.get(0);

  const r4 = await core4.get(0);

  t.is("hello", new util.TextDecoder().decode(r3));
  t.is("world", new util.TextDecoder().decode(r4));

  await store1.close();
  await store2.close();
  t.pass();
});
