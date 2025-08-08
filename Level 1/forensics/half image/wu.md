# Challenge Analysis

The `flag.py` script performs an unusual operation:

1. It opens an image, testfile.png.
2. It splits the image into a left half and a right half.
3. It saves the left half as a standard, viewable PNG file.
4. It converts the right half into raw pixel data using .tobytes().
5. It creates flag.png by concatenating the complete file bytes of the left-half PNG with the raw pixel data of the right half.
6. This results in a flag.png that appears to be only the left side of the image, but it secretly contains the pixel data for the right side appended to the end of the file, past the standard PNG IEND chunk.

# The Recovery Process

To recover the full image, we must reverse the process:

1. **Separate Data:** Open flag.png and separate the valid PNG data (the left half) from the appended raw pixel data (the right half). We can do this by loading the image with Pillow (which only reads the valid PNG part), then re-saving it to a memory buffer to find the exact size of the PNG data stream. Everything after that point in the original file is the raw data for the right half.
2. **Handle Skewing (The Stride):** The raw data from `.tobytes()` isn't just a simple stream of pixels. To optimize memory alignment, image libraries often add padding bytes to the end of each horizontal line (scanline). This full line length is called the "stride". When reconstructing the image from raw bytes, we must tell Pillow what the stride is. Otherwise, it will misinterpret where each line begins, causing the image to appear skewed or slanted. The stride can be calculated by dividing the total size of the raw data by the image's height.
3. **Calculate Correct Width:** A key error was in calculating the width of the right-side image. The number of bytes in the raw data is *`stride * height`*, not `width * 3 * height`. Therefore, the correct width of the right half must be calculated from the stride: `width = stride / 3`. This avoids the off-by-one errors that caused the final visual glitch in the number "0".
4. **Reconstruct:** With the left image loaded, and the right image correctly reconstructed from the raw data, we create a new blank canvas with the combined width of both halves and paste them side-by-side to reveal the complete flag.

# Solution Script
```python
from PIL import Image
import os
from io import BytesIO

flag_image_path = "flag.png"

try:
    # 1. Open flag.png. Pillow will correctly read the valid PNG part (the left half)
    # and ignore the extra raw data appended at the end.
    left_img = Image.open(flag_image_path)
    left_width, height = left_img.size
    
    # 2. Read the entire byte content of the flag.png file.
    with open(flag_image_path, "rb") as f:
        flag_data = f.read()

    # 3. Determine the exact size of the valid PNG data stream.
    # We do this by saving the loaded left_img to a memory buffer and checking its size.
    # This tells us where the raw data begins in the flag_data byte array.
    left_bytes_io = BytesIO()
    left_img.save(left_bytes_io, format='PNG')
    left_png_size = left_bytes_io.tell()

    # 4. Extract the raw pixel data for the right half of the image.
    # It's all the data that comes after the valid PNG stream.
    right_raw_data = flag_data[left_png_size:]

    # 5. Calculate the stride (the number of bytes per horizontal line in the raw data).
    # This is crucial because the raw data may contain padding for memory alignment.
    # Stride = Total raw data size / image height.
    stride = len(right_raw_data) // height

    # 6. Calculate the correct width of the right half.
    # The stride is the width in pixels * 3 bytes/pixel + padding.
    # Since the original image was RGB, we can find the width from the stride.
    # This is more accurate than using the total data length.
    right_width = stride // 3
    
    # 7. Create the right-side image from the raw pixel data.
    # We provide the mode ('RGB'), size, the data itself, and critically, the decoder
    # parameters ('raw', 'RGB', stride) to prevent the image from being skewed.
    right_img = Image.frombytes('RGB', (right_width, height), right_raw_data, 'raw', 'RGB', stride)

    # 8. Create a new blank image to stitch the two halves together.
    total_width = left_width + right_width
    full_img = Image.new('RGB', (total_width, height))

    # 9. Paste the left and right images into the new blank image.
    full_img.paste(left_img, (0, 0))
    full_img.paste(right_img, (left_width, 0))

    # 10. Save and display the final, reconstructed image.
    solved_path = "flag_solved.png"
    full_img.save(solved_path)
    
    print(f"Image successfully recovered and saved to: {solved_path}")
    
    # Open the solved image file (works on Windows).
    os.startfile(solved_path)

except FileNotFoundError:
    print(f"Error: Could not find '{flag_image_path}'.")
    print("Please ensure you have run 'flag.py' to generate it first.")
except Exception as e:
    print(f"An unexpected error occurred: {e}")
```