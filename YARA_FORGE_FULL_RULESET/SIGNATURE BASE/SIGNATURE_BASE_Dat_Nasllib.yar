rule SIGNATURE_BASE_Dat_Nasllib : FILE
{
	meta:
		description = "Chinese Hacktool Set - file NaslLib.dll"
		author = "Florian Roth (Nextron Systems)"
		id = "d5ce72a4-c2b0-50b2-85bb-acf0bfd354e0"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_hacktools.yar#L316-L331"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "fb0d4263118faaeed2d68e12fab24c59953e862d"
		logic_hash = "7d2f3c67fe78028a51ba01c88d7eb62c38fe3c918bb03eee41b6583bc464ad78"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "nessus_get_socket_from_connection: fd <%d> is closed" fullword ascii
		$s2 = "[*] \"%s\" completed, %d/%d/%d/%d:%d:%d - %d/%d/%d/%d:%d:%d" fullword ascii
		$s3 = "A FsSniffer backdoor seems to be running on this port%s" fullword ascii

	condition:
		uint16(0)==0x5a4d and filesize <1360KB and all of them
}
