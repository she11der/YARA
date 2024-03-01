rule MALPEDIA_Win_Sidewinder_Auto : FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "476f112b-78c8-59d9-8623-54ca0fa7fd69"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.sidewinder"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.sidewinder_auto.yar#L1-L134"
		license_url = "N/A"
		logic_hash = "eff1c6e4779cf645096e1bcfd05e39d6cbab1c4bd8a928e81992c305a580a163"
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
		$sequence_0 = { 83a570fdffff00 8b45c4 89853cffffff 8d8544ffffff 50 8b853cffffff 8b00 }
		$sequence_1 = { 50 e8???????? 89852cfbffff e8???????? 8d8568fbffff 50 e8???????? }
		$sequence_2 = { e8???????? 8d45c4 50 8d45a0 50 e8???????? 8d45a0 }
		$sequence_3 = { 8d45e0 50 e8???????? 0fbf45e8 50 ff75e0 e8???????? }
		$sequence_4 = { 7d20 6a30 68???????? ff35???????? ffb534ffffff e8???????? 898504ffffff }
		$sequence_5 = { 8b00 ff7508 ff5004 8b450c 832000 8d45e8 50 }
		$sequence_6 = { e8???????? 8bd0 8d4de8 e8???????? 8d45c8 50 8d45d8 }
		$sequence_7 = { ff5020 dbe2 898528ffffff 83bd28ffffff00 7d1d 6a20 68???????? }
		$sequence_8 = { 8945dc 8d45e4 50 8b45dc 8b00 ff75dc ff5024 }
		$sequence_9 = { ff75b8 ff75d8 6aff 6820110000 e8???????? 83650c00 eb27 }

	condition:
		7 of them and filesize <679936
}
