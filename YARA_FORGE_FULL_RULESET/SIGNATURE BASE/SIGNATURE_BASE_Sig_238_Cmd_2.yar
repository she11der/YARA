import "pe"

rule SIGNATURE_BASE_Sig_238_Cmd_2
{
	meta:
		description = "Disclosed hacktool set (old stuff) - file cmd.jsp"
		author = "Florian Roth (Nextron Systems)"
		id = "5fae3c4a-aeeb-5e02-9071-3980a39a19a9"
		date = "2014-11-23"
		modified = "2023-12-05"
		reference = "https://github.com/Neo23x0/signature-base"
		source_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/yara/thor-hacktools.yar#L2071-L2088"
		license_url = "https://github.com/Neo23x0/signature-base/blob/c04cde449bdf5fb40bb001fb663d32a70f89abe4/LICENSE"
		hash = "be4073188879dacc6665b6532b03db9f87cfc2bb"
		logic_hash = "a794d6b60194a190bd8d549ad00cf90649a52d831fdc7539c68a1f6312609bc2"
		score = 60
		quality = 85
		tags = ""
		license = "Detection Rule License 1.1 https://github.com/Neo23x0/signature-base/blob/master/LICENSE"

	strings:
		$s0 = "Process child = Runtime.getRuntime().exec(" ascii
		$s1 = "InputStream in = child.getInputStream();" fullword ascii
		$s2 = "String cmd = request.getParameter(\"" ascii
		$s3 = "while ((c = in.read()) != -1) {" fullword ascii
		$s4 = "<%@ page import=\"java.io.*\" %>" fullword ascii

	condition:
		all of them
}
