# svx — Python SDK

Python bindings for the SVX client. Every operation runs the same Rust code as
the `svx` command-line tool, so the security checks are identical: local
signature verification before any login, a fresh login bound to each open,
and decryption only after the managed service and the recipient's key agent
both approve.

See [`docs/sdk-python.md`](../../docs/sdk-python.md) for the full guide.

```python
import svx

client = svx.Client()                       # ~/.config/svx/config.toml or $SVX_CONFIG
status = client.status("incident.svx")     # verified locally, no key release
result = client.open("incident.svx", output_dir="~/SVX")
print(result.path)
```
