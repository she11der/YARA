rule MALPEDIA_Win_Session_Manager_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "dc2cef80-2dcf-5809-93bd-82c69da769f0"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.session_manager"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.session_manager_auto.yar#L1-L124"
		license_url = "N/A"
		logic_hash = "603fcab78a4336ae9ff58b2ce6e64cc670272e944fe82c789ba11945e145dd5d"
		score = 75
		quality = 75
		tags = "FILE"
		version = "1"
		tool = "yara-signator v0.6.0"
		signator_config = "callsandjumps;datarefs;binvalue"
		malpedia_rule_date = "20231130"
		malpedia_hash = "fc8a0e9f343f6d6ded9e7df1a64dac0cc68d7351"
		malpedia_version = "20230808"
		malpedia_license = "CC BY-SA 4.0"
		malpedia_sharing = "TLP:WHITE"

	strings:
		$sequence_0 = { 4c89b848240000 4c89b850240000 4c89b858240000 4c89b860240000 4c89b868240000 4c89b870240000 }
		$sequence_1 = { 4c8d35fb2d0100 83e63f 488beb 48c1fd06 48c1e606 498b04ee }
		$sequence_2 = { 4c89b838060000 4c89b840060000 4c89b848060000 4c89b850060000 4c89b858060000 4c89b860060000 4c89b868060000 }
		$sequence_3 = { 4c89b8100b0000 4c89b8180b0000 4c89b8200b0000 4c89b8280b0000 4c89b8300b0000 4c89b8380b0000 }
		$sequence_4 = { 4c89b8c8180000 4c89b8d0180000 4c89b8d8180000 4c89b8e0180000 4c89b8e8180000 4c89b8f0180000 }
		$sequence_5 = { 4c89b890030000 4c89b898030000 4c89b8a0030000 4c89b8a8030000 4c89b8b0030000 4c89b8b8030000 4c89b8c0030000 }
		$sequence_6 = { 4c89b820220000 4c89b828220000 4c89b830220000 4c89b838220000 4c89b840220000 4c89b848220000 4c89b850220000 }
		$sequence_7 = { ff15???????? 488d0df81b0200 ff15???????? 488d0d7b170200 ff15???????? }
		$sequence_8 = { 488d0dd7070000 e8???????? e8???????? 488d0d42070000 e8???????? }
		$sequence_9 = { 4533c9 458d4101 488d542450 488bcb ff90a8000000 }

	condition:
		7 of them and filesize <372736
}
