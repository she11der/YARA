rule SIGNATURE_BASE_Rombertik_Carbongrabber_Panel_Installscript : FILE
{
	meta:
		description = "Detects CarbonGrabber alias Rombertik panel install script - file install.php"
		author = "Florian Roth (Nextron Systems)"
		id = "f6c04e27-bbab-5012-a4f9-71d49d252b83"
		date = "2015-05-05"
		modified = "2023-12-05"
		reference = "http://blogs.cisco.com/security/talos/rombertik"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/crime_rombertik_carbongrabber.yar#L33-L53"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "cd6c152dd1e0689e0bede30a8bd07fef465fbcfa"
		logic_hash = "a0edc53aea21bc317f510a4a463ca677d9dc1ec234ca9824bc46711c851f2ccc"
		score = 75
		quality = 83
		tags = "FILE"
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "$insert = \"INSERT INTO `logs` (`id`, `ip`, `name`, `host`, `post`, `time`, `bro" ascii
		$s3 = "`post` text NOT NULL," fullword ascii
		$s4 = "`host` text NOT NULL," fullword ascii
		$s5 = ") ENGINE=InnoDB  DEFAULT CHARSET=latin1 AUTO_INCREMENT=5 ;\" ;" fullword ascii
		$s6 = "$db->exec($columns); //or die(print_r($db->errorInfo(), true));;" fullword ascii
		$s9 = "$db->exec($insert);" fullword ascii
		$s10 = "`browser` text NOT NULL," fullword ascii
		$s13 = "`ip` text NOT NULL," fullword ascii

	condition:
		filesize <3KB and all of them
}
