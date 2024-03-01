rule SIGNATURE_BASE_Webshell_PHP_C37
{
	meta:
		description = "Web Shell - file c37.php"
		author = "Florian Roth (Nextron Systems)"
		id = "393e738a-b4c2-5630-a55f-c3caee4ff75e"
		date = "2014-01-28"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-webshells.yar#L1771-L1785"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "d01144c04e7a46870a8dd823eb2fe5c8"
		logic_hash = "b93394f4e05cc96c31a8adcb0981aa8b069780893c469b41ece3d3ce92c42251"
		score = 70
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s3 = "array('cpp','cxx','hxx','hpp','cc','jxx','c++','vcproj'),"
		$s9 = "++$F; $File = urlencode($dir[$dirFILE]); $eXT = '.:'; if (strpos($dir[$dirFILE],"

	condition:
		all of them
}
