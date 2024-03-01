rule BINARYALERT_Eicar_Substring_Test
{
	meta:
		description = "Standard AV test, checking for an EICAR substring"
		author = "Austin Byers | Airbnb CSIRT"
		id = "43af8d40-16be-5948-839e-b58cb36c4155"
		date = "2018-04-17"
		modified = "2018-04-17"
		reference = "https://github.com/airbnb/binaryalert/"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/eicar.yara#L20-L34"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "9dc46b273d12d4431b833d4380235b387de4b3aab1f6211b868ada1d1339383a"
		score = 50
		quality = 40
		tags = ""

	strings:
		$eicar_substring = "$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!"

	condition:
		all of them
}
