package is.sort.ghidratek2465;

import java.io.IOException;
import java.io.InputStream;

public class ROMUtils {
	// TODO(siggi): Search ROMs for valid headers and return their location.

	// The recognized scope kinds.
	public enum ScopeKind {
		UNKNOWN,
		TEK2465,
		TEK2465A,
		TEK2465B,
		TEK2465B_LATE,
	}

	// Find the scope kind from part number.
	public static ScopeKind scopeKindFromPartNumber(int part_number) {
		switch (part_number) {
		case 1625:
		case 1626:
		case 1627:
		case 1628:
			return ScopeKind.TEK2465;

		case 3302:
		case 3303:
			return ScopeKind.TEK2465A;

		case 5370:
		case 5371:
			return ScopeKind.TEK2465B;

		case 5876:
		case 5877:
			return ScopeKind.TEK2465B_LATE;

		default:
			return ScopeKind.UNKNOWN;
		}
	}

	// Get the human readable name of a scope kind.
	public static String getScopeKindName(ScopeKind kind) {
		switch (kind) {
		case TEK2465:
			return "Tek2465";
		case TEK2465A:
			return "Tek2465A";
		case TEK2465B:
			return "Tek2465B";
		case TEK2465B_LATE:
			return "Tek2465B SN>B05000";
		default:
			return "Unknown";
		}
	}

	// Computes the checksum of the next `length` bytes in `str`.
	static int checksumRange(InputStream str, int length) throws IOException {
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
