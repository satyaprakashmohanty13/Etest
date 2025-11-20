import streamlit as st
import numpy as np
from PIL import Image
import jpegio as jio
from reedsolo import RSCodec
import os
import io

# ------------------------------
# Robust Steganography Class
# ------------------------------
class RobustSteganography:
    def __init__(self, rs_n=255, rs_k=223):
        self.rs = RSCodec(rs_n - rs_k)
        self.rs_n = rs_n
        self.rs_k = rs_k
        self.coding_table = self._generate_coding_table()

    def _generate_coding_table(self):
        return np.array([
            [0, 1, 5, 6, 14, 15, 27, 28],
            [2, 4, 7, 13, 16, 26, 29, 42],
            [3, 8, 12, 17, 25, 30, 41, 43],
            [9, 11, 18, 24, 31, 40, 44, 53],
            [10, 19, 23, 32, 39, 45, 52, 54],
            [20, 22, 33, 38, 46, 51, 55, 60],
            [21, 34, 37, 47, 50, 56, 59, 61],
            [35, 36, 48, 49, 57, 58, 62, 63]
        ])

    def _zigzag_to_index(self, pos):
        idx = np.where(self.coding_table == pos)
        return idx[0][0], idx[1][0]

    def _get_robust_coefficients(self, dct_block):
        robust = []
        for zz_pos in range(1, 6):
            row, col = self._zigzag_to_index(zz_pos)
            val = dct_block[row, col]
            if val != 0:
                robust.append((row, col, val))
        return robust

    def _embed_in_block(self, dct_block, bits_to_embed):
        coeffs = self._get_robust_coefficients(dct_block)
        if len(coeffs) < len(bits_to_embed):
            return 0

        embedded = 0
        for i, bit in enumerate(bits_to_embed):
            row, col, orig_val = coeffs[i]
            if bit == 1 and orig_val > 0:
                dct_block[row, col] = -orig_val
                embedded += 1
            elif bit == 1 and orig_val < 0:
                dct_block[row, col] = abs(orig_val)
                embedded += 1
        return embedded

    def _extract_from_block(self, dct_block, max_bits):
        coeffs = self._get_robust_coefficients(dct_block)
        bits = []
        for i in range(min(max_bits, len(coeffs))):
            row, col, val = coeffs[i]
            bits.append(1 if val < 0 else 0)
        return bits

    def encode(self, cover_bytes, secret_text):
        try:
            secret_bytes = secret_text.encode('utf-8')
            encoded_bytes = self.rs.encode(secret_bytes)

            bit_stream = np.unpackbits(np.frombuffer(encoded_bytes, dtype=np.uint8))
            bits_to_embed = bit_stream.tolist()

            with open("temp_cover.jpg", "wb") as f:
                f.write(cover_bytes)

            jpeg = jio.read("temp_cover.jpg")
            y_channel = jpeg.coef_arrays[0]

            bits_embedded = 0
            total_blocks = y_channel.shape[0] // 8

            for block_idx in range(total_blocks):
                start_row = block_idx * 8
                block = y_channel[start_row:start_row+8, 0:8].copy()

                chunk_size = 3
                start_bit = bits_embedded
                end_bit = min(start_bit + chunk_size, len(bits_to_embed))
                if start_bit >= len(bits_to_embed):
                    break

                chunk = bits_to_embed[start_bit:end_bit]
                embedded = self._embed_in_block(block, chunk)

                if embedded > 0:
                    y_channel[start_row:start_row+8, 0:8] = block
                    bits_embedded += embedded

            if bits_embedded < len(bits_to_embed):
                return False, "Image too small to hide message"

            jpeg.coef_arrays[0] = y_channel
            jpeg.write("stego_output.jpg")

            with open("stego_output.jpg", "rb") as f:
                return True, f.read()

        except Exception as e:
            return False, str(e)

    def decode(self, stego_bytes):
        try:
            with open("temp_stego.jpg", "wb") as f:
                f.write(stego_bytes)

            jpeg = jio.read("temp_stego.jpg")
            y_channel = jpeg.coef_arrays[0]

            extracted_bits = []
            total_blocks = y_channel.shape[0] // 8

            for block_idx in range(total_blocks):
                start_row = block_idx * 8
                block = y_channel[start_row:start_row+8, 0:8]
                extracted_bits.extend(self._extract_from_block(block, 3))

            if len(extracted_bits) < 8:
                return False, "No hidden message found"

            byte_array = []
            for i in range(0, len(extracted_bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(extracted_bits):
                        byte = (byte << 1) | extracted_bits[i + j]
                byte_array.append(byte)

            byte_data = bytes(byte_array)

            try:
                decoded_bytes = self.rs.decode(byte_data)
                text = decoded_bytes[0].decode("utf-8", errors="ignore")
                return True, text
            except:
                return True, byte_data.decode("utf-8", errors="ignore")

        except Exception as e:
            return False, str(e)


# -------------------------------------
# Streamlit Interface
# -------------------------------------

st.title("🔐 JPEG Compression-Resistant Steganography Tool")
st.write("Hide & extract text inside JPEG images using robust DCT-based encoding.")

stego = RobustSteganography()

tab1, tab2 = st.tabs(["🟣 Encode Message", "🔵 Decode Message"])

# ------------------------------
# ENCODE TAB
# ------------------------------
with tab1:
    st.header("📤 Hide Secret Message Inside JPEG")

    cover = st.file_uploader("Upload cover JPEG image", type=["jpg", "jpeg"])
    secret = st.text_area("Enter secret message")

    if st.button("Encode & Download Stego Image"):
        if cover and secret.strip():
            success, result = stego.encode(cover.read(), secret.strip())
            if success:
                st.success("Message successfully embedded!")
                st.download_button(
                    "Download Stego Image",
                    data=result,
                    file_name="stego.jpg",
                    mime="image/jpeg"
                )
            else:
                st.error(result)
        else:
            st.error("Please select image & enter message.")

# ------------------------------
# DECODE TAB
# ------------------------------
with tab2:
    st.header("📥 Extract Hidden Message")

    stego_file = st.file_uploader("Upload stego JPEG image", type=["jpg", "jpeg"])

    if st.button("Extract Message"):
        if stego_file:
            success, text = stego.decode(stego_file.read())
            if success:
                st.success("Message extracted:")
                st.code(text)
            else:
                st.error(text)
        else:
            st.error("Please upload the stego image.")
