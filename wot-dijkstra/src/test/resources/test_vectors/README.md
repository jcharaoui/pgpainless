<!--
SPDX-FileCopyrightText: 2022 Paul Schaub <vanitasvitae@fsfe.org>

SPDX-License-Identifier: Apache-2.0
-->
# Test Vectors

The `freshly_generated/` directory contains freshly generated test vectors.
Those are keys and certificates without any third-party signatures.

```mermaid
graph TD;
  Foo Bank CA <ca@foobank.com>;
  Foo Bank Employee <employee@foobank.com>;
  Foo Bank Admin <admin@foobank.com>;
  Customer <customer@example.com>;
```