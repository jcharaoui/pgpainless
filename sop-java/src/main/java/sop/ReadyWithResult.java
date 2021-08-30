/*
 * Copyright 2021 Paul Schaub.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package sop;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.OutputStream;

import sop.exception.SOPGPException;

public abstract class ReadyWithResult<T> {

    /**
     * Write the data eg. decrypted plaintext to the provided output stream and return the result of the
     * processing operation.
     *
     * @param outputStream output stream
     * @return result, eg. signatures
     *
     * @throws IOException in case of an IO error
     * @throws SOPGPException.NoSignature
     */
    public abstract T writeTo(OutputStream outputStream) throws IOException, SOPGPException.NoSignature;

    public ByteArrayAndResult<T> toBytes() throws IOException, SOPGPException.NoSignature {
        ByteArrayOutputStream bytes = new ByteArrayOutputStream();
        T result = writeTo(bytes);
        return new ByteArrayAndResult<>(bytes.toByteArray(), result);
    }
}