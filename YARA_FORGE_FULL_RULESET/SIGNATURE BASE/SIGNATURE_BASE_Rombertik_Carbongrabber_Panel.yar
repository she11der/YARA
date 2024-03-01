rule SIGNATURE_BASE_Rombertik_Carbongrabber_Panel : FILE
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik Panel - file index.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"
		date = "2015-05-05"
		modified = "2023-12-05"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_rombertik_carbongrabber.yar#L55-L73"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "e6e9e4fc3772ff33bbeeda51f217e9149db60082"
		logic_hash = "8b7fde3c3894b7aa83e05f6a1b820195276f8738fde218485c0465afaed88427"
		score = 75
		quality = 85
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "echo '<meta http-equiv=\"refresh\" content=\"0;url=index.php?a=login\">';" fullword ascii
		$s1 = "echo '<meta http-equiv=\"refresh\" content=\"2;url='.$website.'/index.php?a=login" ascii
		$s2 = "header(\"location: $website/index.php?a=login\");" fullword ascii
		$s3 = "$insertLogSQL -> execute(array(':id' => NULL, ':ip' => $ip, ':name' => $name, ':" ascii
		$s16 = "if($_POST['username'] == $username && $_POST['password'] == $password){" fullword ascii
		$s17 = "$SQL = $db -> prepare(\"TRUNCATE TABLE `logs`\");" fullword ascii

	condition:
		filesize <46KB and all of them
}
