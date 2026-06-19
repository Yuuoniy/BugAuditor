# Installation

## Docker

Build the artifact image:

```bash
docker build -t bugauditor-ae .
docker run -it bugauditor-ae
```

The image provides the required analysis tools, including Weggli, tree-sitter-c, and Joern.

## Source Code

```bash
mkdir -p source
curl -L https://www.kernel.org/pub/linux/kernel/v6.x/testing/linux-6.10-rc4.tar.xz -o /tmp/linux-6.10-rc4.tar.xz
tar -xf /tmp/linux-6.10-rc4.tar.xz -C source
mv source/linux-6.10-rc4 source/linux
```

You can prepare other open-source projects you wish to analyze (e.g., OpenSSL, FFmpeg, or your own codebase).
The artifact supports projects placed under `source/`; update `program_paths` in `config.json` when using different paths.


## LLM endpoint Configuration
The main configuration file is `config.json`. You need to configure your own LLM endpoint before running the artifact. Edit the following fields according to your provider:

`openai_api_base`: The base URL of your LLM API endpoint
`openai_api_key`: Your API key
`openai_model`: The model name (e.g., deepseek-v4-flash, or any compatible model)

Example configuration:
```json
{
  "openai_api_base": "https://api.deepseek.com",
  "openai_api_key": "YOUR_KEY",
  "openai_model": "deepseek-v4-flash"
}
```
Note on models: During our artifact evaluation preparation, we used DeepSeek V4 Flash for testing. Its cost is equal to or lower than that of DeepSeek V3.2. The artifact is compatible with other similar models from DeepSeek or other OpenAI-compatible providers.
