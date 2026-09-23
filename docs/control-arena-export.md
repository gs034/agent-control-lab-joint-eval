# ControlArena directory export

**Brand:** Agent Control Lab. **Licence:** Apache-2.0.

## What it is

`python -m joint_eval.control_arena_export --out <dir>` writes three files from `eval/joint_story/` fixtures and frozen `expected_receipt.json` files:

| File | Contents |
| --- | --- |
| `trajectory.jsonl` | One sample per joint-story row. Keys match the ControlArena directory writer: `rating`, `notes`, `desc`, `other`, `raw_state`, `metadata`, `scores`, `models` |
| `tools.json` | Tool definitions named by those fixtures (`name`, `description`, `input_schema`) |
| `metadata.json` | `source_file`, `format`, `output_format`, `eval_id`, `created`, `total_samples`, plus honesty fields |

`raw_state` is a JSON string of message blocks in the Anthropic tool-use object shape (`tool_use` / `tool_result`). The blocks are assembled from the envelope, any sidecar fixture (`observed_head.json`, `runtime.json`, `untrusted_prose.txt`), and the frozen receipt. No model API is called.

The rug-pull row is one sample with two tool results: pinned `ALLOW`, then `DENY` `head_mismatch`.

## What it is not

- Not a ControlArena setting.
- Not an Inspect eval loop, task, or `.eval` log. `inspect_loop` and `inspect_eval_log` are false. ControlArena and Inspect are not imported and are not dependencies.
- Not a measured attack-success table. `rating` is JSON null. `scores` is empty. `models` is empty. `residual_asr` is JSON null. **No ASR.**
- Not a change to the public/EOI claim cite (`1d0f380`) or to the sibling install pins.

The export shape can be written from receipts and fixtures alone. An Inspect loop is not required to produce these three files.
