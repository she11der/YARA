rule MALPEDIA_Win_Powerduke_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "6d856194-c9fe-5330-9bd8-d5a96e01d2f2"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.powerduke"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.powerduke_auto.yar#L1-L113"
		license_url = "N/A"
		logic_hash = "8396f645fb90ff46635658086ca415f6d857b1da2dac7ff489b34d4ef5885286"
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
		$sequence_0 = { c705????????00000000 6a04 6800300000 ff7518 }
		$sequence_1 = { ff75e4 ff75bc ff15???????? 09c0 7473 }
		$sequence_2 = { 6a00 ff15???????? 09c0 0f8412010000 8945e4 53 50 }
		$sequence_3 = { b801000000 c9 c20c00 55 89e5 81ec080c0000 }
		$sequence_4 = { 89f7 31c9 803c0f3a 7409 }
		$sequence_5 = { 09c0 7505 b850000000 8945ec c6040e00 }
		$sequence_6 = { c70000000000 837d2000 740f 8b4520 }
		$sequence_7 = { c20400 55 89e5 56 57 8b750c }
		$sequence_8 = { 0f8493000000 c745f901000000 89c3 be???????? }
		$sequence_9 = { 6a00 57 ff15???????? 09c0 }

	condition:
		7 of them and filesize <57344
}