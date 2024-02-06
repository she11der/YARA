rule BINARYALERT_Ransomware_Windows_Lazarus_Wannacry___FILE
{
	meta:
		description = "Rule based on shared code between Feb 2017 Wannacry sample and Lazarus backdoor from Feb 2015 discovered by Neel Mehta"
		author = "Costin G. Raiu, Kaspersky Lab"
		id = "6335bd03-0625-5856-891c-9a5decd7e00f"
		date = "2017-08-11"
		modified = "2017-08-11"
		reference = "https://twitter.com/neelmehta/status/864164081116225536"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/ransomware/windows/ransomware_windows_lazarus_wannacry.yara#L3-L32"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "dddff5f74bf3f11baf1d3853d6cb5e5b1e0c5e75445c421d4d5145f7a496fc4b"
		score = 75
		quality = 80
		tags = "FILE"
		md5_1 = "9c7c7149387a1c79679a87dd1ba755bc"
		md5_2 = "ac21c8ad899727137c4b94458d7aa8d8"

	strings:
		$a1 = {
        51 53 55 8B 6C 24 10 56 57 6A 20 8B 45 00 8D 75
        04 24 01 0C 01 46 89 45 00 C6 46 FF 03 C6 06 01
        46 56 E8 }
}
