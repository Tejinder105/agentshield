"""Framework-specific adapters. Each submodule here requires its target
framework to be installed (see the `openai-agents` and `langchain`
extras) and is therefore *not* imported by this package's top-level
`__init__.py` -- import the specific submodule you need directly, e.g.
`from agentshield_sdk.integrations.openai_agents import shielded_function_tool`.
"""
