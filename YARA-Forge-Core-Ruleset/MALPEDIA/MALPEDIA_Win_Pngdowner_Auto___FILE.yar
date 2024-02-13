rule MALPEDIA_Win_Pngdowner_Auto___FILE
{
	meta:
		description = "autogenerated rule brought to you by yara-signator"
		author = "Felix Bilstein - yara-signator at cocacoding dot com"
		id = "31e7b95d-0a01-5118-aefe-72f10c1de52f"
		date = "2023-12-06"
		modified = "2023-12-08"
		reference = "https://malpedia.caad.fkie.fraunhofer.de/details/win.pngdowner"
		source_url = "https://github.com/malpedia/signator-rules//blob/fbacfc09b84d53d410385e66a8e56f25016c588a/rules/win.pngdowner_auto.yar#L1-L125"
		license_url = "N/A"
		logic_hash = "73611f5253baf7f95cf22059dc76ddead3ab9941ef229c965d83aeede8e284a3"
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
		$sequence_0 = { 8b4508 c705????????01000000 50 a3???????? e8???????? 8db6bcdc4000 bf???????? }
		$sequence_1 = { ff15???????? 85c0 a3???????? 741b 6a00 6a00 }
		$sequence_2 = { 7552 833c8580e0400000 53 57 }
		$sequence_3 = { c74050c0b54000 c7401401000000 c3 56 57 ff15???????? }
		$sequence_4 = { c1ff05 83e11f 8b3cbd40e64000 8d0cc9 8d3c8f eb05 bf???????? }
		$sequence_5 = { 83c8ff 5b 81c420000100 c3 8b3d???????? 8d4c2420 }
		$sequence_6 = { ff74240c e8???????? 83c40c c3 e8???????? 8b4c2404 894814 }
		$sequence_7 = { c3 33c0 5e c3 8b442404 c74050c0b54000 }
		$sequence_8 = { 8b1d???????? b900400000 33c0 8d7c2420 8d542420 }
		$sequence_9 = { ff742404 e8???????? 59 c3 56 8bf1 6a1b }

	condition:
		7 of them and filesize <131072
}