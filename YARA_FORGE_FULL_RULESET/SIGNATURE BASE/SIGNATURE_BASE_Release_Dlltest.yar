rule SIGNATURE_BASE_Release_Dlltest
{
	meta:
		description = "Webshells Auto-generated - file dllTest.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "af821252-8409-5572-9014-59e8c5feaacd"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L8216-L8236"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "76a59fc3242a2819307bb9d593bef2e0"
		logic_hash = "ba759ae1bbde357085b2b2dfda0780b5a239a44b4e999244e8eceed246090ce3"
		score = 50
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = ";;;Y;`;d;h;l;p;t;x;|;"
		$s1 = "0 0&00060K0R0X0f0l0q0w0"
		$s2 = ": :$:(:,:0:4:8:D:`=d="
		$s3 = "4@5P5T5\\5T7\\7d7l7t7|7"
		$s4 = "1,121>1C1K1Q1X1^1e1k1s1y1"
		$s5 = "9 9$9(9,9P9X9\\9`9d9h9l9p9t9x9|9"
		$s6 = "0)0O0\\0a0o0\"1E1P1q1"
		$s7 = "<.<I<d<h<l<p<t<x<|<"
		$s8 = "3&31383>3F3Q3X3`3f3w3|3"
		$s9 = "8@;D;H;L;P;T;X;\\;a;9=W=z="

	condition:
		all of them
}
