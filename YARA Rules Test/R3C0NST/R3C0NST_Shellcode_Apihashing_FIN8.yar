rule R3C0NST_Shellcode_Apihashing_FIN8
{
	meta:
		description = "Detects FIN8 Shellcode APIHashing"
		author = "Frank Boldewin (@r3c0nst)"
		id = "a5b4a925-c4cc-5d3a-a2f1-3372f77ceea2"
		date = "2021-03-16"
		modified = "2021-03-25"
		reference = "https://www.bitdefender.com/files/News/CaseStudies/study/394/Bitdefender-PR-Whitepaper-BADHATCH-creat5237-en-EN.pdf"
		source_url = "https://github.com/fboldewin/YARA-rules//blob/54e9e6899b258b72074b2b4db6909257683240c2/Shellcode.APIHashing.FIN8.yar#L1-L74"
		license_url = "N/A"
		logic_hash = "958d6a3c0c78ad22fb56896d6a97b9fe79c56813dc36a37385f3ce5621008624"
		score = 75
		quality = 90
		tags = ""

	strings:
		$APIHashing32bit1 = {68 F2 55 03 88 68 65 19 6D 1E}
		$APIHashing32bit2 = {68 9B 59 27 21 C1 E9 17 33 4C 24 10 68 37 5C 32 F4}
		$APIHashing64bit = {49 BF 65 19 6D 1E F2 55 03 88 49 BE 37 5C 32 F4 9B 59 27 21}

	condition:
		all of ($APIHashing32bit*) or $APIHashing64bit
}