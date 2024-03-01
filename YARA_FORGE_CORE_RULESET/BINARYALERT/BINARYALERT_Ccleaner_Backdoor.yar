rule BINARYALERT_Ccleaner_Backdoor
{
	meta:
		description = "Ccleaner 5.33 backdoor with a possible APT17/Group72 connection."
		author = "@fusionrace"
		id = "769e4fcb-9638-5a5b-8b73-a1cda3bc286a"
		date = "2017-12-14"
		modified = "2017-12-14"
		reference = "http://blog.talosintelligence.com/2017/09/ccleaner-c2-concern.html"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/malware/windows/malware_windows_ccleaner_backdoor.yara#L1-L15"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "ce3fc54d58e337ab17e6f1ba7745c593210483c02ed3969059a8fe6682d87218"
		score = 75
		quality = 80
		tags = ""
		md5_1 = "d488e4b61c233293bec2ee09553d3a2f"
		md5_2 = "b95911a69e49544f9ecc427478eb952f"
		md5_3 = "063b58879c8197b06d619c3be90506ec"
		md5_4 = "7690e414e130acf7c962774c05283142"

	strings:
		$s1 = "s:\\workspace\\ccleaner\\branches\\v5.33" fullword ascii wide

	condition:
		$s1
}
