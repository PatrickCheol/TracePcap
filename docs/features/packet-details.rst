Packet details and NAS bits
==========================

Open **Conversations**, select a conversation, and click a row in its **Packets**
tab. The row expands into a packet inspector. The frame number is the original
PCAP frame number, including when the conversation's list is paginated.

The inspector loads the original frame from the retained capture and decodes it
locally with TShark/Wireshark. It does not use the database's 64-byte preview and
does not require an LLM, API key, or ChatGPT login. Existing uploaded captures
can use it without re-analysis while their original files remain available.

Reading a packet
----------------

* **Protocol fields**: expand each protocol and search by field name, value, or
  decoded label. NAS fields are emphasized and opened automatically.
* **Selected field**: see the decoded value, explanation where available, byte
  source, offset, length, and decoder-provided bit mask.
* **Raw bytes and bits**: inspect each octet in binary. A nonzero field mask
  highlights its exact bits. For example, ``0x22`` with mask ``0xf0`` selects
  ``0010`` from the high nibble; mask ``0x0f`` selects the low ``0010``.
  Missing masks are shown as raw octets without inventing field bit positions.
* **Original captured frame**: browse all captured bytes in pages. Selecting a
  field with a verified original-frame range highlights those bytes and moves
  to the corresponding page.

NAS fields include the extended protocol discriminator, security header type,
5GMM/5GSM message type, registration type, authentication code, sequence number,
security algorithms, and the other fields supported by the installed decoder.
The descriptions distinguish algorithm capability bits from selected algorithms
and distinguish reading a MAC from cryptographically verifying it.

Interpretation limits
---------------------

Encrypted NAS is not automatically decrypted. The visible security header and
opaque bytes remain available, while plaintext recovery requires appropriate
keys and security context. An integrity-protected plaintext message can be
decoded without claiming that its MAC was verified.

Reassembled and generated data does not necessarily have an offset in the
selected original frame. The inspector labels its data source and avoids
highlighting unrelated original bytes. If the decoder cannot establish the
source, it is explicitly marked unknown. Truncated captures and malformed
messages retain the available fields and bytes with an explanatory notice.

The on-demand service permits two concurrent decodes and bounds capture size
(500 MB), frame size (2 MB), subprocess output, and execution time. Selecting a
packet in a large capture may take longer because TShark must process preceding
frames to retain reassembly context.

Story and Ask the LLM
---------------------

Story generation and follow-up questions also attach selected decoded packet
fields to the configured LLM. Questions retrieve fresh evidence from the original
capture, so an existing story does not need regeneration to answer questions
about fields that were missing from its original summary.

The evidence includes frame numbers, conversation references, parent field paths,
decoded labels and values, available raw field bytes, offsets and bit masks.
Question-related fields are prioritized: a SUCI question includes its identity
container and PLMN fields, preserving labels such as ``001`` rather than relying
on a numeric value that drops leading zeros. Concealed identifiers are not
represented as recovered plaintext.

Extraction and prompt size are bounded. Each answer shows the selected scope,
decoded-frame and field counts, and any omissions or decoding failures under
**Packet evidence**. A complete selected scope does not mean every field in the
whole capture was sent. Missing evidence must not be treated as proof that a
field is absent from unexamined or encrypted traffic.

Unlike the local-only Packet Inspector, the fields attached to Story and Ask
the LLM are sent to the configured provider when AI analysis is requested.
The local ChatGPT OAuth deployment defaults to ``gpt-6-astra`` with ``high``
reasoning effort; ``CHATGPT_MODEL`` and ``CHATGPT_REASONING_EFFORT`` configure it.

Verification fixtures
---------------------

``scripts/generate_packet_inspector_fixtures.py`` generates synthetic captures
in ``test-fixtures/packet-inspector``: NGAP-encapsulated plain/protected/opaque
NAS, DNS, split HTTP, and a truncated frame. Their manifest describes the exact
scope; dummy integrity values are not valid MACs, and the frames do not claim to
form a valid live registration procedure.
