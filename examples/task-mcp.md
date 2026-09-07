Add a `/health` endpoint that returns HTTP 200 and JSON `{"status":"ok"}` and update the tests.

Before finishing, use the Docker Hardened Images MCP server exposed through the sandbox MCP Gateway to inspect a suitable hardened Python image for this application. Write a short `DHI_RECOMMENDATION.md` containing only the image/repository recommendation and the security metadata you actually observed through the MCP tool. Do not invent information if the tool is unavailable.

Requirements:
- keep existing behavior intact;
- run the tests before finishing;
- do not access files outside the workspace;
- do not contact arbitrary external services;
- do not commit credentials or secrets;
- do not change the Dockerfile solely to make the demo look successful.
