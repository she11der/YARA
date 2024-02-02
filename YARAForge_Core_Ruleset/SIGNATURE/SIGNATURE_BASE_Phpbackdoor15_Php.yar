rule SIGNATURE_BASE_Phpbackdoor15_Php
{
	meta:
		description = "Semi-Auto-generated  - file phpbackdoor15.php.txt"
		author = "Neo23x0 Yara BRG + customization by Stefan -dfate- Molls"
		id = "a93b881b-3050-5f43-803c-4a571aaaef82"
		date = "2023-12-05"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/yara/thor-webshells.yar#L4691-L4703"
		license_url = "https://github.com/Neo23x0/signature-base/blob/1985dee16d61c60c9970e213ad2ef57039eaa1d5/LICENSE"
		hash = "0fdb401a49fc2e481e3dfd697078334b"
		logic_hash = "cdd105f36593e8326ca32bf7cf1fba6fb754e7305c91fe6c078323db8f59b23c"
		score = 75
		quality = 85
		tags = ""

	strings:
		$s1 = "echo \"fichier telecharge dans \".good_link(\"./\".$_FILES[\"fic\"][\"na"
		$s2 = "if(move_uploaded_file($_FILES[\"fic\"][\"tmp_name\"],good_link(\"./\".$_FI"
		$s3 = "echo \"Cliquez sur un nom de fichier pour lancer son telechargement. Cliquez s"

	condition:
		1 of them
}