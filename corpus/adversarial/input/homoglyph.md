# Homoglyph fixture

The first line spells the company name with Latin characters: Vantor.

The next line uses a Cyrillic а (U+0430) in the same position: Vаntor.

A detector matching on exact bytes will find one and miss the other. Both must
be reported, or the second form leaks a name the vault already knows.
