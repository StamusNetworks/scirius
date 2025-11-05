import pytest

from pygments.token import Name, Keyword, Punctuation
import pygments.token as t

from rules.suripyg import SuriLexer, SuriHTMLFormat


@pytest.fixture(scope="module")
def suri_lexer():
    """Returns an instance of the SuriLexer for testing."""
    return SuriLexer(encoding="utf-8")


# --- Lexer Tests: SuriLexer ---


def test_lexer_metadata():
    """Test tokenization of metadata block."""
    lexer = SuriLexer()
    text = "metadata: tag custom, service http;"
    tokens = list(lexer.get_tokens(text))

    assert tokens[0] == (t.Keyword, "metadata:")

    assert tokens[2] == (Name.Variable, "tag")
    assert tokens[4] == (Name.Attribute, "custom")

    assert tokens[-2] == (Punctuation, ";")


def test_lexer_reference():
    """Test tokenization of reference block."""
    lexer = SuriLexer()
    text = "reference: url,https://example.com/ref-id;"
    tokens = list(lexer.get_tokens(text))

    assert tokens[0] == (Keyword, "reference:")

    # Reference block: (url)(,)( ) (https://example.com/ref-id)
    assert tokens[2] == (Name.Variable, "url")
    assert tokens[3] == (Punctuation, ",")
    assert tokens[4] == (Name.Attribute, "https://example.com/ref-id")
    assert tokens[-2] == (Punctuation, ";")


@pytest.mark.parametrize(
    "rule_part, expected_type",
    [
        # Actions (Keyword.Type)
        ("alert ", t.Keyword.Type),
        ("pass ", t.Keyword.Type),
        ("drop ", t.Keyword.Type),
        ("ruletype ", t.Keyword.Type),
        # Protocols (Keyword.Constant)
        ("tcp ", t.Keyword.Constant),
        ("icmp ", t.Keyword.Constant),
        # Variables (Name.Variable / IP)
        ("$HOME_NET", t.Name.Variable),
        ("any ", t.Name.Variable),
        ("192.168.1.1/24 ", t.Name.Variable),
        # Keywords/Options (Keyword)
        ("sid: ", t.Keyword),
        ("msg: ", t.Keyword),
        ("content: ", t.Keyword),
        ("byte_jump: ", t.Keyword),
        ("flowbits: ", t.Keyword),
        ("tls.subject: ", t.Keyword),
        # Option Modifiers (Name.Attribute)
        ("nocase", t.Name.Attribute),
        ("norm", t.Name.Attribute),
        ("relative", t.Name.Attribute),
        ("to_client", t.Name.Attribute),
        # Operators
        ("->", t.Operator),
        ("<>", t.Operator),
        # Punctuation
        (";", t.Punctuation),
    ],
)
def test_lexer_root_tokens(suri_lexer, rule_part, expected_type):
    """Test tokenization of common Suricata rule components in the root state."""
    # Add whitespace and another token to ensure boundary check (excluding metadata/reference)
    test_text = rule_part + " "
    tokens = list(suri_lexer.get_tokens(test_text))

    # Check the primary token and ensure it's at the start (ignoring leading whitespace if any)
    assert tokens[0][1].strip() in rule_part.strip()
    assert tokens[0][0] == expected_type


def test_lexer_fancy_strings():
    """Test tokenization of fancy quotes (Unicode quotes)."""
    lexer = SuriLexer()
    text = 'content:"fancy string with hex |00 11|";'
    tokens = list(lexer.get_tokens(text))

    assert tokens[-4][0] == t.Number.Hex
    assert tokens[4][0] == t.String


# --- Formatting Function Tests: SuriHTMLFormat ---


class MockRule:
    """Mock class representing the Django Rule object."""

    def __init__(self, rule_content):
        self.rule_content = rule_content

    def __str__(self):
        # Assuming the formatting function takes the object and converts it to string
        # or the code is intended to be used on rule.body (which is not available)
        # We will test the function directly with a string, which is what `highlight` expects.
        return self.rule_content


def test_suri_html_format_output_type(suri_lexer):
    """Test that SuriHTMLFormat returns a string (HTML output)."""
    rule_string = 'alert http $HOME_NET any -> $EXTERNAL_NET any (msg:"Test Rule"; sid:1000001;)'

    # The function SuriHTMLFormat takes a string (rule) and returns highlighted HTML
    html_output = SuriHTMLFormat(rule_string)

    assert isinstance(html_output, str)
    assert html_output.startswith('<div class="highlight">')
    assert '<span class="kt">alert</span>' in html_output
    assert '<span class="k">sid:</span>' in html_output  # Ensure lexer worked
    assert '<span class="k">msg:</span>' in html_output  # Ensure lexer worked


def test_suri_html_format_comment():
    """Test that comments are correctly formatted as HTML comments."""
    rule_string = '# This is a comment\nalert tcp any any -> any any (msg:"Test";)'
    html_output = SuriHTMLFormat(rule_string)

    # Pygments Comment class renders as <span class="c">
    assert '<span class="c"># This is a comment</span>' in html_output
