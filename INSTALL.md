# Installation

## Docker

Build the artifact image:

```bash
docker build -t bugauditor-ae .
docker run -it bugauditor-ae
```

For detailed dependency information, please refer to the [Dockerfile](./Dockerfile).

## Source Code

```bash
mkdir -p source
curl -L https://github.com/torvalds/linux/archive/refs/tags/v6.10-rc4.tar.gz -o /tmp/linux-v6.10-rc4.tar.gz
tar -xzf /tmp/linux-v6.10-rc4.tar.gz -C source
mv source/linux-6.10-rc4 source/linux
```

You can prepare other open-source projects you wish to analyze (e.g., OpenSSL, FFmpeg, or your own codebase).
The artifact supports projects placed under `source/`; update `program_paths` in `config.json` when using different paths.


## LLM endpoint Configuration
The main configuration file is `config.json`. You need to configure your own LLM endpoint before running the artifact. Edit the following fields according to your provider:

```json
{
  "openai_api_base": "https://api.deepseek.com", //The base URL of your LLM API endpoint
  "openai_api_key": "YOUR_KEY", // Your API key
  "openai_model": "deepseek-v4-flash" //The model name (e.g., deepseek-v4-flash, or any compatible model)
}
```
Note on models: During our artifact evaluation preparation, we used DeepSeek V4 Flash for testing. Its cost is equal to or lower than that of DeepSeek V3.2. The artifact is compatible with other LLMs via OpenAI-compatible endpoints.
