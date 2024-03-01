rule SIGNATURE_BASE_Item_Old : FILE
{
	meta:
		description = "Chinese Hacktool Set - file item-old.php"
		author = "Florian Roth (Nextron Systems)"
		id = "c32bbd48-a363-53c7-84c6-c47581e2f9da"
		date = "2015-06-13"
		modified = "2023-12-05"
		reference = "http://tools.zjqhr.com/"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/gen_cn_webshells.yar#L157-L172"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "daae358bde97e534bc7f2b0134775b47ef57e1da"
		logic_hash = "181e46408050490dccc4f321bd1072da0436d920e16cc4711b16425eb5bd73ed"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s1 = "$sCmd = \"wget -qc \".escapeshellarg($sURL).\" -O \".$sFile;" fullword ascii
		$s2 = "$sCmd = \"convert \".$sFile.\" -flip -quality 80 \".$sFileOut;" fullword ascii
		$s3 = "$sHash = md5($sURL);" fullword ascii

	condition:
		filesize <7KB and 2 of them
}
