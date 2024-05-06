package is.sort.GhidraTek2465;

import java.io.IOException;
import java.io.InputStream;

public class ROMUtils {
	// Computes the checksum of the next `length` bytes in `str`.
	static int ChecksumRange(InputStream str, int length) throws IOException {
		int checksum = 0;
		byte data[] = null;

		str.read(data, 0, length);
		for (int i = 0; i < data.length; ++i) {
			checksum <<= 1;
			checksum += data[i] + (checksum >> 16);
			checksum &= 0xFFFF;
		}

		return checksum;
	}
}
