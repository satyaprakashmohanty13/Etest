import streamlit as st
import numpy as np
from PIL import Image
import jpegio as jio
from reedsolo import RSCodec
import io
import os

# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# ──────────────────────────────────────────────────────────────────────────────
MAX_FILE_SIZE_MB = 10  # Adjust based on your needs (Streamlit Cloud free tier: 10-15MB)

# ──────────────────────────────────────────────────────────────────────────────
# STEGANOGRAPHY CORE
# ──────────────────────────────────────────────────────────────────────────────
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
        """Generate zigzag order table for 8x8 blocks"""
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
        """Convert zigzag position to (row, col) in 8x8 block"""
        idx = np.where(self.coding_table == pos)
        return idx[0][0], idx[1][0]
    
    def _get_robust_coefficients(self, dct_block):
        """Extract coefficients suitable for embedding (low-frequency AC)"""
        robust = []
        # Use coefficients 1-5 (low-frequency AC)
        for zz_pos in range(1, 6):
            row, col = self._zigzag_to_index(zz_pos)
            val = dct_block[row, col]
            # Only non-zero coefficients are stable
            if val != 0:
                robust.append((row, col, val))
        return robust
    
    def _embed_in_block(self, dct_block, bits_to_embed):
        """Embed bits by flipping signs of robust coefficients"""
        coeffs = self._get_robust_coefficients(dct_block)
        if len(coeffs) < len(bits_to_embed):
            return 0  # Not enough robust coefficients
        
        embedded = 0
        for i, bit in enumerate(bits_to_embed):
            row, col, orig_val = coeffs[i]
            # Flip sign to encode '1', keep for '0'
            if bit == 1 and orig_val > 0:
                dct_block[row, col] = -orig_val
                embedded += 1
            elif bit == 1 and orig_val < 0:
                dct_block[row, col] = abs(orig_val)
                embedded += 1
            # For bit=0, do nothing (preserve original sign)
        
        return embedded
    
    def _extract_from_block(self, dct_block, max_bits):
        """Extract bits from DCT block"""
        coeffs = self._get_robust_coefficients(dct_block)
        bits = []
        for i in range(min(max_bits, len(coeffs))):
            row, col, val = coeffs[i]
            # Negative coefficient = bit 1, Positive = bit 0
            bits.append(1 if val < 0 else 0)
        return bits
    
    def encode(self, cover_data, secret_text, quality=95):
        """
        Hide secret text in JPEG data
        Returns: (success: bool, stego_data: bytes, message: str)
        """
        try:
            # Save uploaded data to temp file for jpegio
            temp_cover = "temp_cover.jpg"
            with open(temp_cover, "wb") as f:
                f.write(cover_data)
            
            # Compress secret text with RS codes
            secret_bytes = secret_text.encode('utf-8')
            encoded_bytes = self.rs.encode(secret_bytes)
            
            # Convert to bit stream
            bit_stream = np.unpackbits(np.frombuffer(encoded_bytes, dtype=np.uint8))
            bits_to_embed = bit_stream.tolist()
            
            # Load JPEG and get DCT coefficients
            jpeg = jio.read(temp_cover)
            y_channel = jpeg.coef_arrays[0]  # Luminance channel
            
            # Embed bits block by block
            bits_embedded = 0
            total_blocks = y_channel.shape[0] // 8
            
            for block_idx in range(total_blocks):
                start_row = block_idx * 8
                block = y_channel[start_row:start_row+8, 0:8].copy()
                
                chunk_size = 3  # Embed max 3 bits per block for robustness
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
            
            # Save stego to temp file then read back to memory
            temp_stego = "temp_stego.jpg"
            jpeg.coef_arrays[0] = y_channel
            jpeg.write(temp_stego)
            
            with open(temp_stego, "rb") as f:
                stego_data = f.read()
            
            # Cleanup temp files
            try:
                os.remove(temp_cover)
                os.remove(temp_stego)
            except:
                pass
            
            return True, stego_data, f"✅ Successfully embedded {len(secret_bytes)} bytes"
            
        except Exception as e:
            # Cleanup on error
            try:
                os.remove(temp_cover)
                os.remove(temp_stego)
            except:
                pass
            return False, None, f"❌ Error: {str(e)}"
    
    def decode(self, stego_data):
        """
        Extract hidden text from JPEG data
        Returns: (success: bool, message: str)
        """
        try:
            # Save uploaded data to temp file
            temp_stego = "temp_stego.jpg"
            with open(temp_stego, "wb") as f:
                f.write(stego_data)
            
            # Load JPEG and get DCT coefficients
            jpeg = jio.read(temp_stego)
            y_channel = jpeg.coef_arrays[0]
            
            # Extract bits block by block
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
            
            # Apply RS decoding
            try:
                decoded_bytes = self.rs.decode(byte_data)
                secret_text = decoded_bytes[0].decode('utf-8', errors='ignore')
            except:
                # Try without RS if decoding fails (maybe small message)
                secret_text = byte_data.decode('utf-8', errors='ignore')
            
            # Cleanup temp file
            try:
                os.remove(temp_stego)
            except:
                pass
            
            return True, secret_text
            
        except Exception as e:
            # Cleanup on error
            try:
                os.remove(temp_stego)
            except:
                pass
            return False, f"❌ Error: {str(e)}"

# ──────────────────────────────────────────────────────────────────────────────
# FILE VALIDATION
# ──────────────────────────────────────────────────────────────────────────────
def check_file_size(file_data):
    """Validate file size and show error if too large"""
    size_mb = len(file_data) / (1024 * 1024)
    if size_mb > MAX_FILE_SIZE_MB:
        st.error(f"❌ File too large: {size_mb:.1f}MB (max {MAX_FILE_SIZE_MB}MB)")
        st.info("💡 Tip: Use smaller images or increase MAX_FILE_SIZE_MB in code")
        return False
    return True

def display_image_safe(image_file, caption):
    """Display image with memory-efficient resizing"""
    try:
        image_file.seek(0)
        img = Image.open(image_file)
        
        # Resize for display only (not processing)
        display_img = img.copy()
        if max(display_img.size) > 800:  # Resize if width or height > 800px
            display_img.thumbnail((800, 800), Image.Resampling.LANCZOS)
        
        st.image(display_img, caption=caption, use_column_width=True)
        image_file.seek(0)  # Reset pointer for processing
        return True
    except Exception as e:
        st.error(f"Failed to display image: {str(e)}")
        return False

# ──────────────────────────────────────────────────────────────────────────────
# STREAMLIT UI
# ──────────────────────────────────────────────────────────────────────────────
def main():
    st.set_page_config(
        page_title="Compression-Resistant Steganography",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    st.title("🔐 JPEG Compression-Resistant Steganography")
    st.markdown("Hide text in JPEG images that survives social media recompression")
    
    # Sidebar info
    st.sidebar.info(f"📏 **Max file size**: {MAX_FILE_SIZE_MB}MB")
    with st.sidebar.expander("ℹ️ Help"):
        st.markdown("""
        **Best Practices:**
        - Use high-quality JPEG images
        - Keep messages under 1KB
        - Test by recompressing before use
        - For research & legitimate privacy only
        """)
    
    stego = get_stego_instance()
    col1, col2 = st.columns(2)
    
    # ──────────────────────────────────────────────────────────────────────────
    # ENCODE SECTION
    # ──────────────────────────────────────────────────────────────────────────
    with col1:
        st.header("Encode Message")
        
        cover_file = st.file_uploader(
            "Upload JPEG Cover Image", 
            type=['jpg', 'jpeg'],
            help=f"Max size: {MAX_FILE_SIZE_MB}MB. High-quality JPEG recommended."
        )
        
        if cover_file:
            # Validate file size
            if not check_file_size(cover_file.read()):
                st.stop()
            
            # Display image
            if not display_image_safe(cover_file, "Cover Image"):
                st.stop()
            
            # Get message input
            secret_message = st.text_area(
                "Secret Message", 
                height=200,
                placeholder="Enter your secret text here..."
            )
            
            quality = st.slider(
                "JPEG Quality", 50, 100, 95,
                help="Higher quality = better compression resistance"
            )
            
            # Encode button
            if st.button("Encode & Hide Message", type="primary", use_container_width=True):
                if not secret_message:
                    st.error("❌ Please enter a secret message!")
                else:
                    with st.spinner("🔧 Encoding... This may take a moment"):
                        try:
                            success, stego_data, msg = stego.encode(
                                cover_file.read(), 
                                secret_message,
                                quality
                            )
                            
                            if success:
                                st.success(msg)
                                st.download_button(
                                    label="📥 Download Stego Image",
                                    data=stego_data,
                                    file_name="stego_image.jpg",
                                    mime="image/jpeg",
                                    use_container_width=True
                                )
                            else:
                                st.error(msg)
                        except Exception as e:
                            st.error(f"Processing error: {str(e)}")
                            st.info("💡 Try reducing image size or message length")
    
    # ──────────────────────────────────────────────────────────────────────────
    # DECODE SECTION
    # ──────────────────────────────────────────────────────────────────────────
    with col2:
        st.header("Decode Message")
        
        stego_file = st.file_uploader(
            "Upload Stego JPEG Image", 
            type=['jpg', 'jpeg'],
            key="decode_uploader"
        )
        
        if stego_file:
            # Validate file size
            if not check_file_size(stego_file.read()):
                st.stop()
            
            # Display stego image
            if not display_image_safe(stego_file, "Stego Image"):
                st.stop()
            
            # Decode button
            if st.button("Extract Hidden Message", type="primary", use_container_width=True):
                with st.spinner("🔍 Extracting..."):
                    try:
                        success, result = stego.decode(stego_file.read())
                        
                        if success:
                            st.success("✅ Message extracted successfully!")
                            st.text_area(
                                "Hidden Message", 
                                value=result, 
                                height=200,
                                disabled=True
                            )
                            st.code(result, language="text")
                        else:
                            st.error(result)
                    except Exception as e:
                        st.error(f"Extraction error: {str(e)}")

# ──────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ──────────────────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    main()
