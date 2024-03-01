rule BINARYALERT_Eicar_Av_Test
{
	meta:
		description = "This is a standard AV test, intended to verify that BinaryAlert is working correctly."
		author = "Austin Byers | Airbnb CSIRT"
		id = "4dbb9d9d-9a8b-56f0-878a-a4a362a2c4f8"
		date = "2018-04-17"
		modified = "2018-04-17"
		reference = "http://www.eicar.org/86-0-Intended-use.html"
		source_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/rules/public/eicar.yara#L1-L18"
		license_url = "https://github.com/airbnb/binaryalert//blob/a9c0f06affc35e1f8e45bb77f835b92350c68a0b/LICENSE"
		logic_hash = "870db233ca083fae19a88a109e13d086c76df2340b709eb2da565c08574a42bd"
		score = 50
		quality = 80
		tags = ""

	strings:
		$eicar_regex = /^X5O!P%@AP\[4\\PZX54\(P\^\)7CC\)7\}\$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!\$H\+H\*\s*$/

	condition:
		all of them
}
