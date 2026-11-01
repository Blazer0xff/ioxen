const fs = require("fs");
const path = require("path");

const root = path.resolve(__dirname, "..");

const files = [
  ["agent/ios_script_bundle.js", "src/ioxen/runtime/agent/ios_script_bundle.js"],
  ["config/ios_hooks.json", "src/ioxen/runtime/config/ios_hooks.json"],
];

for (const [source, target] of files) {
  const sourcePath = path.join(root, source);
  const targetPath = path.join(root, target);
  fs.mkdirSync(path.dirname(targetPath), { recursive: true });
  fs.copyFileSync(sourcePath, targetPath);
}
