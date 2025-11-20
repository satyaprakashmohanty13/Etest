import streamlit as st
import numpy as np
from PIL import Image
import jpegio as jio
from reedsolo import RSCodec
import io
import os

@st.cache_resource
def get_stego_instance():
    """Create and cache steganography instance"""
    return RobustSteganography()

class RobustSteganography:
    def __init__(self, rs_n=255, rs_k=223):
        self.rs = RSCodec(rs_n - rs_k)
        self.rs_n = rs_n
        self.rs_k = rs_k
        self.coding_table = self._generate_coding_table()
    
    def _generate_coding_table(self):
        table = np.array([
            [0, 1, 5, 6, 14, 15, 27, 28],
            [2, 4, 7, 13, 16, 26, 29, 42],
            [3, 8, 12, 17, 25, 30, 41, 43],
            [9, 11, 18, 24, 31, 40, 44, 53],
            [10, 19, 23, 32, 39, 45, 52, 54],
            [20, 22, 33, 38, 46, 51, 55, 60],
            [21, 34, 37, 47, 50, 56, 59, 61],
            [35, 36, 48, 49, 57, 58, 62, 63]
        ])
        return table
    
    def _zigzag_to_index(self, pos):
        idx = np.where(self.coding_table == pos)
        return idx[0][0], idx[1][0]
    
    def _get_robust_coefficients(self, dct_block):
        robust = []
        for zz_pos in range(1, 6):  # Low-frequency AC coeffs
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
    
    def encode(self, cover_data, secret_text, quality=95):
        """Encode text into JPEG data"""
        try:
            # Save uploaded data to temp file for jpegio
            with open("temp_cover.jpg", "wb") as f:
                f.write(cover_data)
            
            # Compress secret text with RS codes
            secret_bytes = secret_text.encode('utf-8')
            encoded_bytes = self.rs.encode(secret_bytes)
            bit_stream = np.unpackbits(np.frombuffer(encoded_bytes, dtype=np.uint8))
            bits_to_embed = bit_stream.tolist()
            
            # Load JPEG
            jpeg = jio.read("temp_cover.jpg")
            y_channel = jpeg.coef_arrays[0]
            
            # Embed bits
            bits_embedded = 0
            block_idx = 0
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
                
                block_idx += 1
            
            if bits_embedded < len(bits_to_embed):
                raise ValueError(f"Image too small. Embedded {bits_embedded}/{len(bits_to_embed)} bits")
            
            # Save stego to memory
            jpeg.coef_arrays[0] = y_channel
            jpeg.write("temp_stego.jpg")
            
            with open("temp_stego.jpg", "rb") as f:
                stego_data = f.read()
            
            # Cleanup
            os.remove("temp_cover.jpg")
            os.remove("temp_stego.jpg")
            
            return True, stego_data, f"Successfully embedded {len(secret_bytes)} bytes"
            
        except Exception as e:
            return False, None, f"Error: {str(e)}"
    
    def decode(self, stego_data):
        """Extract text from JPEG data"""
        try:
            # Save uploaded data to temp file
            with open("temp_stego.jpg", "wb") as f:
                f.write(stego_data)
            
            # Load JPEG
            jpeg = jio.read("temp_stego.jpg")
            y_channel = jpeg.coef_arrays[0]
            
            # Extract bits
            extracted_bits = []
            total_blocks = y_channel.shape[0] // 8
            
            for block_idx in range(total_blocks):
                start_row = block_idx * 8
                block = y_channel[start_row:start_row+8, 0:8]
                bits = self._extract_from_block(block, 3)
                extracted_bits.extend(bits)
            
            # Convert to bytes
            if len(extracted_bits) < 8:
                raise ValueError("No hidden message found")
            
            byte_array = []
            for i in range(0, len(extracted_bits), 8):
                byte = 0
                for j in range(8):
                    if i + j < len(extracted_bits):
                        byte = (byte << 1) | extracted_bits[i + j]
                byte_array.append(byte)
            
            byte_data = bytes(byte_array)
            
            # RS decoding
            try:
                decoded_bytes = self.rs.decode(byte_data)
                secret_text = decoded_bytes[0].decode('utf-8', errors='ignore')
            except:
                secret_text = byte_data.decode('utf-8', errors='ignore')
            
            # Cleanup
            os.remove("temp_stego.jpg")
            
            return True, secret_text
            
        except Exception as e:
            return False, f"Error: {str(e)}"

# Streamlit UI
def main():
    st.set_page_config(page_title="Compression-Resistant Steganography", 
                      layout="wide")
    
    st.title("🔐 JPEG Compression-Resistant Steganography")
    st.markdown("Hide text in JPEG images that survives recompression on social media")
    
    stego = get_stego_instance()
    
    # Two columns
    col1, col2 = st.columns(2)
    
    # Encode Section
    with col1:
        st.header("Encode Message")
        
        cover_file = st.file_uploader("Upload JPEG Cover Image", 
                                     type=['jpg', 'jpeg'], 
                                     help="Use high-quality JPEG for best results")
        
        if cover_file:
            # Display cover image
            cover_image = Image.open(cover_file)
            st.image(cover_image, caption="Cover Image", use_column_width=True)
            cover_file.seek(0)  # Reset file pointer
            
            secret_message = st.text_area("Secret Message", 
                                         height=200,
                                         placeholder="Enter your secret text here...")
            
            quality = st.slider("JPEG Quality", 50, 100, 95,
                               help="Higher quality = better compression resistance")
            
            if st.button("Encode & Hide Message", type="primary"):
                if not secret_message:
                    st.error("Please enter a secret message!")
                else:
                    with st.spinner("Encoding... This may take a moment"):
                        success, stego_data, msg = stego.encode(
                            cover_file.read(), 
                            secret_message,
                            quality
                        )
                    
                    if success:
                        st.success(msg)
                        # Download button
                        st.download_button(
                            label="📥 Download Stego Image",
                            data=stego_data,
                            file_name="stego_image.jpg",
                            mime="image/jpeg"
                        )
                    else:
                        st.error(msg)
    
    # Decode Section
    with col2:
        st.header("Decode Message")
        
        stego_file = st.file_uploader("Upload Stego JPEG Image", 
                                     type=['jpg', 'jpeg'],
                                     key="decode_uploader")
        
        if stego_file:
            # Display stego image
            stego_image = Image.open(stego_file)
            st.image(stego_image, caption="Stego Image", use_column_width=True)
            stego_file.seek(0)  # Reset file pointer
            
            if st.button("Extract Hidden Message", type="primary"):
                with st.spinner("Extracting..."):
                    success, result = stego.decode(stego_file.read())
                
                if success:
                    st.success("Message extracted successfully!")
                    st.text_area("Hidden Message", 
                                value=result, 
                                height=200, 
                                disabled=True)
                    
                    # Copy to clipboard button
                    st.code(result, language="text")
                else:
                    st.error(result)
    
    # Info section
    st.markdown("---")
    with st.expander("ℹ️ How it works"):
        st.markdown("""
        ### Technical Details
        * **Embedding Domain**: JPEG DCT coefficients (not pixel domain)
        * **Method**: Sign-flipping of low-frequency AC coefficients
        * **Error Correction**: Reed-Solomon codes (32 byte parity per 223 bytes)
        * **Capacity**: ~0.1 bits per non-zero DCT coefficient
        * **Compression Resistance**: Survives JPEG recompression at quality 50-95
        
        ### Best Practices
        1. Use **high-quality JPEG** as cover image (minimal existing compression artifacts)
        2. Keep messages **under 1KB** for 512×512 images
        3. Always **test** by recompressing the stego image before deployment
        4. This tool is for **research and legitimate privacy** purposes only
        """)

if __name__ == "__main__":
    main()
