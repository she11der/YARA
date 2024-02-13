rule MALPEDIA_Win_Onionduke_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "bc18bebb-924f-5db1-bda1-575db25c40f5"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.onionduke"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.onionduke_auto.yar#L1-L117"
		license_url = "N/A"
		logic_hash = "2b5a6150c91e41c1ea04d8a66d543531da34a08cde94cd3e5e729e90a4473cac"
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
		$sequence_0 = { 33d2 895e68 66895658 8b550c 8d4202 c645fc04 8945ec }
		$sequence_1 = { c1e81f 03c2 897dcc 0f84d0000000 897dd0 eb02 }
		$sequence_2 = { 384b01 7506 40 380c18 }
		$sequence_3 = { 894ee4 894ffc 8d4eec 8d57ec 8d5fec }
		$sequence_4 = { 56 8bf1 837e0c00 751e 6a04 e8???????? 83c404 }
		$sequence_5 = { 3bfb 72ac 5f 5e }
		$sequence_6 = { 8b4e44 8b09 85d2 7405 }
		$sequence_7 = { 8910 894ed0 8b56e0 8957e0 8b56e4 }
		$sequence_8 = { e8???????? 83c404 33c0 eb66 8bc6 8d5001 }
		$sequence_9 = { 80f90f 7f05 80c157 eb02 32c9 }

	condition:
		7 of them and filesize <671744
}