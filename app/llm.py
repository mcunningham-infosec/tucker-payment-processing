"""
llm.py - a thin adapter around the AI model, so the model can be swapped.

GeminiLLM talks to Google Gemini with function calling (tools). FakeLLM is a scripted stand-in
used by the automated tests, so the guardrails can be tested without calling (or paying for)
a real model. Both return the same simple ModelTurn object.
"""
from dataclasses import dataclass, field

from .config import SETTINGS


@dataclass
class ModelTurn:
    """One model response: text and/or requested tool calls, plus token counts for the spend cap."""
    text: str = ""
    tool_calls: list = field(default_factory=list)    # list of (name, args_dict)
    tokens_in: int = 0
    tokens_out: int = 0
    raw: object = None                               # provider-specific content, echoed back on the next round


class GeminiLLM:
    """Google Gemini via the google-genai SDK. Automatic function calling is OFF: our code runs every tool."""

    def __init__(self, api_key: str = "", model: str = ""):
        """Create the client; the API key comes from the server environment only."""
        from google import genai
        from google.genai import types
        self.types = types
        self.model = model or SETTINGS.gemini_model
        self.client = genai.Client(api_key=api_key or SETTINGS.gemini_api_key)

    def generate(self, system_prompt: str, messages: list, tool_declarations: list) -> ModelTurn:
        """Send the conversation and tool list; return text or tool calls (never auto-executed)."""
        t = self.types
        contents = []
        for m in messages:
            if m["role"] == "user":
                contents.append(t.Content(role="user", parts=[t.Part(text=m["text"])]))
            elif m["role"] == "model":
                contents.append(m["raw"] if m.get("raw") is not None else
                                t.Content(role="model", parts=[t.Part(text=m["text"])]))
            elif m["role"] == "tool":
                contents.append(t.Content(role="user", parts=[
                    t.Part.from_function_response(name=m["name"], response={"result": m["result"]})]))
        config = t.GenerateContentConfig(
            system_instruction=system_prompt,
            tools=[t.Tool(function_declarations=[t.FunctionDeclaration(**d) for d in tool_declarations])],
            automatic_function_calling=t.AutomaticFunctionCallingConfig(disable=True),
            temperature=0.3,
            max_output_tokens=600,
            # Minimal "thinking": faster replies, and thinking tokens are billed as output.
            thinking_config=t.ThinkingConfig(thinking_level="minimal"),
        )
        resp = self.client.models.generate_content(model=self.model, contents=contents, config=config)
        usage = resp.usage_metadata
        calls = [(fc.name, dict(fc.args or {})) for fc in (resp.function_calls or [])]
        raw = resp.candidates[0].content if resp.candidates else None
        text = "" if calls else (resp.text or "")
        return ModelTurn(text=text, tool_calls=calls, raw=raw,
                         tokens_in=getattr(usage, "prompt_token_count", 0) or 0,
                         # Thinking tokens are billed at the output rate, so count them too.
                         tokens_out=(getattr(usage, "candidates_token_count", 0) or 0)
                                    + (getattr(usage, "thoughts_token_count", 0) or 0))


class FakeLLM:
    """Scripted model for tests: returns the queued ModelTurns in order."""

    def __init__(self, turns):
        """Queue the responses this fake model will give."""
        self.turns = list(turns)
        self.seen = []

    def generate(self, system_prompt, messages, tool_declarations) -> ModelTurn:
        """Record what the model was sent and return the next scripted turn."""
        self.seen.append(list(messages))
        return self.turns.pop(0) if self.turns else ModelTurn(text="Woof!")
