using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using uFr;

namespace ufr_apdu_credit_card_reader_examples_csharp_wpf
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
            txtDllVersion.Text = uFCoder.GetLibraryVersion();
        }

        private void btnReaderOpen_Click(object sender, RoutedEventArgs e)
        {

            uint status = 0;

            status = uFCoder.ReaderClose();

            if (chkAdvanced.IsChecked == true)
            {                
                string reader_type = txtReaderType.Text;
                string port_name = txtPortName.Text;
                string port_interface = txtPortInterface.Text;
                string arg = txtArg.Text;

                try
                {
                    UInt32 reader_type_int = Convert.ToUInt32(reader_type);
                    UInt32 port_interface_int = (UInt32)port_interface[0];

                    status = (UInt32)uFCoder.ReaderOpenEx(reader_type_int, port_name, port_interface_int, arg);
                    if (status == 0)
					{
						uFCoder.ReaderUISignal(1, 1);
					}
                }
                catch (Exception er)
                {
                    MessageBox.Show("Invalid Advanced options parameters, please check your input and try again!");
                }
            }
            else
            {

                status = uFCoder.ReaderOpen();

                if (status == 0)
                {
                    uFCoder.ReaderUISignal(1, 1);
                    
                }
                
            }

            txtStatus.Text = uFCoder.status2str(status);
        }

        private void btnReaderReset_Click(object sender, RoutedEventArgs e)
        {
            uint status = uFCoder.ReaderReset();
            txtStatus.Text = uFCoder.status2str(status);
        }

        private void btnReaderClose_Click(object sender, RoutedEventArgs e)
        {
            uint status = uFCoder.ReaderClose();
            txtStatus.Text = uFCoder.status2str(status);

        }

        private void btnGetPAN_Click(object sender, RoutedEventArgs e)
        {
            uint status = 0;
            string df_name = "";
            byte[] pan = new byte[128];

            if (rbPSE1.IsChecked == true)
            {
                df_name = "1PAY.SYS.DDF01";
            } else if (rbPSE2.IsChecked == true)
            {
                df_name = "2PAY.SYS.DDF01";
            } else
            {
                MessageBox.Show("Select Payment System Environment first.");
                return;
            }

            status = uFCoder.SetISO14443_4_Mode();            
            
            status = uFCoder.EMV_GetPAN(df_name, pan);
            txtStatus.Text = uFCoder.status2str(status);
            if (status == (uint) UFR_STATUS.UFR_OK)
            {
                var str = System.Text.Encoding.ASCII.GetString(pan);
                str = str.Substring(0, str.IndexOf((char)0));
                str = System.Text.RegularExpressions.Regex.Replace(str, "....", "$0-");
                str = str.Substring(0, str.Length - 1);

                txtPAN.Text = str;
            }
            else
            {
                txtPAN.Text = "";
            }
            
            uFCoder.s_block_deselect(100);
        }

        private void btnCheckPSE_Click(object sender, RoutedEventArgs e)
        {
            uint status = 0;
            string df_name = "";
            string PseTitle = "";

            if (rbPSE1.IsChecked == true)
            {
                df_name = "1PAY.SYS.DDF01";
                PseTitle = "PSE1";
            }
            else if (rbPSE2.IsChecked == true)
            {
                df_name = "2PAY.SYS.DDF01";
                PseTitle = "PSE2";
            }
            else
            {
                MessageBox.Show("Select Payment System Environment first.");
                return;
            }

            txtCheckPSE.Clear();

            byte[] r_apdu = new byte[258];
            byte[] sw = new byte[2];
            byte[] sfi = new byte[1];
            byte record = 0;
            byte cnt = 0;
            uint ufr_status = 0x54;
            int[] emv_status = new int[1];

            emv_tree_node_t head = new emv_tree_node_t();
            emv_tree_node_t temp = new emv_tree_node_t();
            emv_tree_node_t tail = new emv_tree_node_t();

            byte[] ascii_name = Encoding.ASCII.GetBytes(df_name);

            int[] Ne = new int[1];
            Ne[0] = 256;

            do
            {

                ufr_status = uFCoder.SetISO14443_4_Mode();
                if (ufr_status != 0)
                {
                    txtCheckPSE.AppendText(" Error while switching into ISO 14443-4 mode, check uFR status.");
                    txtStatus.Text = uFCoder.status2str(ufr_status);
                    break;
                }

                txtCheckPSE.AppendText(++cnt + ". Issuing \"Select PSE\" command (" + PseTitle + ")\n" + " [C] 00 A4 04 00 ");
                for (int i = 0; i < df_name.Length; i++)
                {
                    txtCheckPSE.AppendText(ascii_name[i].ToString("X2") + " ");
                }

                ufr_status = uFCoder.APDUTransceive((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, df_name.ToCharArray(), df_name.Length, r_apdu, Ne, (byte)1, sw);
                if (ufr_status != 0)
                {
                    Console.WriteLine(" Error while executing APDU command, check uFR status.");
                    txtStatus.Text = uFCoder.status2str(ufr_status);
                    break;
                }
                else
                {
                    if (sw[0] != (byte)0x90)
                    {
                        txtCheckPSE.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
                        txtCheckPSE.AppendText("\nCould not continue execution due to an APDU error.\n");
                        ufr_status = (uint) UFR_STATUS.UFR_APDU_TRANSCEIVE_ERROR;
                        txtStatus.Text = uFCoder.status2str(ufr_status);
                        break;
                    }

                    if (Ne[0] > 0)
                    {
                        txtCheckPSE.AppendText("\n APDU command executed: response data length = " + Ne[0] + " bytes\n");
                        txtCheckPSE.AppendText(" [R] ");
                        for (int i = 0; i < Ne[0]; i++)
                        {
                            txtCheckPSE.AppendText(r_apdu[i].ToString("X2") + " ");
                        }
                    }

                    txtCheckPSE.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");

                }

                int[] Ne_ptr = new int[1];
                Ne_ptr[0] = Ne[0];

                head = uFCoder.newEmvTag(head, r_apdu, Ne_ptr, false, emv_status);

                if (emv_status[0] != 0)
                {
                    txtCheckPSE.AppendText("EMV parsing error code:" + uFCoder.status2str((uint) emv_status[0]));
                    ufr_status = (uint) emv_status[0];
                    break;
                }

                ufr_status = (uint) uFCoder.getSfi(head, sfi);
                
                if (ufr_status == 0)
                {
                    cnt = 2;
                    record = 1;
                    do
                    {
						++cnt;
						txtCheckPSE.AppendText("\n " + cnt.ToString() + ". Issuing \"Read Record\" command (record = " + record.ToString() + ", sfi = " + sfi.ToString() + "):\n [C] 00 B2" + record.ToString("X2") + ((sfi[0] << 3) | 4).ToString("X2") + "\n");
						ufr_status = (uint) uFCoder.emvReadRecord(r_apdu, Ne_ptr, sfi[0], record, sw);
                        if (ufr_status == 0)
                        {
                            temp = uFCoder.newEmvTag(temp, r_apdu, Ne_ptr, false, emv_status);
                            ufr_status = (uint) emv_status[0];
                            if (record == 1)
                                head.next = tail = temp;
                            else
                            {
                                tail.next = temp;
                                tail = tail.next;
                            }
                        }
                        else
                        {
                            if (sw[0] != (byte)0x90)
                            {
								txtCheckPSE.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
								txtCheckPSE.AppendText("\nCould not continue execution due to an APDU error.\n");
                            }

                            if (Ne[0] > 0)
                            {
                                txtCheckPSE.AppendText("\n APDU command executed: response data length = " + Ne[0] + " bytes\n");
                                txtCheckPSE.AppendText(" [R] ");
                                for (int i = 0; i < Ne[0]; i++)
                                {
                                    txtCheckPSE.AppendText(String.Format("%02X ", r_apdu[i]));
                                }
                            }

							txtCheckPSE.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");

						}

                        record++;
                        cnt++;
                    } while (ufr_status == 0);
                }
                ufr_status = 0;

                txtCheckPSE.AppendText("\n--------------------------------------------------------------------------------------------------------------------------------------\n");
                txtCheckPSE.AppendText("          Card supports Payment System Environment: " + PseTitle);
                txtCheckPSE.AppendText("\n=============================================================================\n");

            } while (false);

            txtStatus.Text = uFCoder.status2str(ufr_status);
            uFCoder.s_block_deselect((byte)100);

        }

        private void btnClearCheckPSE_Click(object sender, RoutedEventArgs e)
        {
            txtCheckPSE.Clear();
        }

        private void btnReadEMV_Click(object sender, RoutedEventArgs e)
        {
			String df_name = "";
			String PseTitle = "";
			if (rbPSE1.IsChecked == true)
			{
				df_name = "1PAY.SYS.DDF01";
				PseTitle = "PSE1";
			}
			else if (rbPSE2.IsChecked == true)
			{
				df_name = "2PAY.SYS.DDF01";
				PseTitle = "PSE2";
			}
			else
			{
				MessageBox.Show("Select Payment System Environment first.");
				return;
			}

			txtReadEMV.Clear();

			byte[] r_apdu = new byte[258];
			int[] Ne = new int[1];
			Ne[0] = 256;

			byte[] sw = new byte[2];
			byte[] sfi = new byte[1];
			byte record = 0;
			byte cnt = 0;
			uint ufr_status = 0x54;
			int[] emv_status = new int[1];
			bool head_attached = false;
			byte[] aid = new byte[16];
			char[] chr_aid = new char[16];
			byte[] aid_len = new byte[1];

			short[] gpo_data_field_size = new short[1];
			byte[] gpo_data_field = new byte[1024];
			byte[] afl_list_count = new byte[1];
			byte[] ascii_name = Encoding.ASCII.GetBytes(df_name);

			emv_tree_node_t head = new emv_tree_node_t();
			emv_tree_node_t temp = new emv_tree_node_t();
			emv_tree_node_t tail = new emv_tree_node_t();
			afl_list_item_t[] afl_list_item = new afl_list_item_t[1];

			do
			{

				ufr_status = uFCoder.SetISO14443_4_Mode();
				if (ufr_status != 0)
				{
					txtReadEMV.AppendText(" Error while switching into ISO 14443-4 mode, check uFR status.");
					txtStatus.Text = uFCoder.status2str(ufr_status);
					break;
				}

				txtReadEMV.AppendText(++cnt + ". Issuing \"Select PSE\" command (" + PseTitle + ")\n" + " [C] 00 A4 04 00 ");
				for (int i = 0; i < df_name.Length; i++)
				{
					txtReadEMV.AppendText(ascii_name[i].ToString("X2") + " ");
				}

				ufr_status = uFCoder.APDUTransceive((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, df_name.ToCharArray(), df_name.Length, r_apdu, Ne, (byte)1, sw);
				if (ufr_status != 0)
				{
					
					txtStatus.Text = uFCoder.status2str(ufr_status);
					break;
				}
				else
				{
					if (sw[0] != (byte)0x90)
					{
						txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
						txtReadEMV.AppendText("\nCould not continue execution due to an APDU error.\n");
						ufr_status = (uint) UFR_STATUS.UFR_APDU_TRANSCEIVE_ERROR;
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}

					if (Ne[0] > 0)
					{
						txtReadEMV.AppendText("\n APDU command executed: response data length = " + Ne[0] + " bytes\n");
						txtReadEMV.AppendText(" [R] ");
						for (int i = 0; i < Ne[0]; i++)
						{
							txtReadEMV.AppendText(r_apdu[i].ToString("X2") + " ");
						}
					}

					txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
				}

				int[] Ne_ptr = new int[1];
				Ne_ptr[0] = Ne[0];

				head = uFCoder.newEmvTag(head, r_apdu, Ne_ptr, false, emv_status);

				if (emv_status[0] != 0)
				{
					txtReadEMV.AppendText(" EMV parsing error occurred.");
					ufr_status = (uint) emv_status[0];
					txtStatus.Text = uFCoder.status2str(ufr_status);
					break;
				}

				ufr_status = (uint) uFCoder.getSfi(head, sfi);
				if (ufr_status == 0)
				{
					record = 1;
					do
					{
						++cnt;
						txtReadEMV.AppendText("\n " + cnt.ToString() + ". Issuing \"Read Record\" command (record = " + record.ToString() + ", sfi = " + sfi.ToString() + "):\n [C] 00 B2" + record.ToString("X2") + ((sfi[0] << 3) | 4).ToString("X2") + "\n");

						ufr_status = (uint) uFCoder.emvReadRecord(r_apdu, Ne_ptr, sfi[0], record, sw);
						if (ufr_status == 0)
						{
							temp = uFCoder.newEmvTag(temp, r_apdu, Ne_ptr, false, emv_status);
							if (record == 1)
								head.next = tail = temp;
							else
							{
								tail.next = temp;
								tail = tail.next;
							}
							if (Ne_ptr[0] > 0)
							{
								txtReadEMV.AppendText(" APDU command executed: response data length = " + Ne[0] + " bytes\n");
								txtReadEMV.AppendText(" [R] ");
								for (int i = 0; i < Ne[0]; i++)
								{
									txtReadEMV.AppendText(r_apdu[i].ToString("X2") + " ");
								}
							}
							txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");

						}
						else
						{
							if (sw[0] != 0x90)
							{
								txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
								txtReadEMV.AppendText(" There is no records");
							}
						}

						record++;
						cnt++;
					} while (ufr_status == 0);

				}

				ufr_status = (uint) uFCoder.getAid(head, aid, aid_len);
				if (ufr_status == 0)
				{
					++cnt;
					txtReadEMV.AppendText("\n" + cnt.ToString() + ". Issuing \"Select the application\" command \n  [C] 00 A4 04 00 " + aid_len[0].ToString("X2") + "\n");
					Ne[0] = 256;
					Array.Copy(aid, chr_aid, aid.Length);
					ufr_status = uFCoder.APDUTransceive((byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, chr_aid, aid_len[0], r_apdu, Ne, (byte)1, sw);
					if (ufr_status != 0)
					{
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}
					else
					{
						if (sw[0] != (byte)0x90)
						{
							txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
							txtReadEMV.AppendText("\nCould not continue execution due to an APDU error.\n");
						}

						if (Ne[0] > 0)
						{
							txtReadEMV.AppendText(" APDU command executed: response data length = " + Ne[0] + " bytes\n");
							txtReadEMV.AppendText(" [R] ");
							for (int i = 0; i < Ne[0]; i++)
							{
								txtReadEMV.AppendText(r_apdu[i].ToString("X2") + " ");
							}
						}
						txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
					}

					Ne_ptr[0] = Ne[0];

					temp = uFCoder.newEmvTag(temp, r_apdu, Ne_ptr, false, emv_status);
					if (emv_status[0] != 0)
					{
						break;
					}
					if (head_attached == false)
					{
						head.next = tail = temp;
						head_attached = true;
					}
					else
					{
						tail.next = temp;
						tail = tail.next;
					}
					++cnt;
					txtReadEMV.AppendText("\n" + cnt.ToString() + ". Formating \"Get Processing Options\" instruction (checking PDOL)\n");
					emv_status[0] = uFCoder.formatGetProcessingOptionsDataField(temp, gpo_data_field, gpo_data_field_size);
					if (emv_status[0] != 0)
					{
						ufr_status = (uint) emv_status[0];
						txtReadEMV.AppendText(" EMV parsing error occurred.");
						ufr_status = (uint) emv_status[0];
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}
					++cnt;
					txtReadEMV.AppendText("\n" + cnt.ToString() + ". Issuing \"Get Processing Options\" command:\n  [C] 80 A8 00 00 " + gpo_data_field_size[0].ToString("X2") + "\n");
					for (int i = 0; i < gpo_data_field_size[0]; i++)
					{
						txtReadEMV.AppendText(String.Format("%02X", gpo_data_field[i]) + " ");
					}

					Ne[0] = 256;
					ufr_status = uFCoder.APDUTransceive_Bytes(0x80, 0xA8, 0x00, 0x00, gpo_data_field, gpo_data_field_size[0], r_apdu, Ne, 1, sw);
					if (ufr_status != 0)
					{
						txtReadEMV.AppendText(" Error while executing APDU command, uFR status is: " + uFCoder.status2str(ufr_status));
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}
					else
					{
						if (sw[0] != (byte)0x90)
						{
							txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
							txtReadEMV.AppendText("\nCould not continue execution due to an APDU error.\n");
							break;
						}

						if (Ne[0] > 0)
						{
							txtReadEMV.AppendText("\n APDU command executed: response data length = " + Ne[0] + " bytes\n");
							txtReadEMV.AppendText(" [R] ");
							for (int i = 0; i < Ne[0]; i++)
							{
								txtReadEMV.AppendText(r_apdu[i].ToString("X2") + " ");
							}
						}
						txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");
					}

					Ne_ptr[0] = Ne[0];
					temp = uFCoder.newEmvTag(temp, r_apdu, Ne_ptr, false, emv_status);
					if (emv_status[0] != 0)
					{
						ufr_status = (uint) emv_status[0];
						txtReadEMV.AppendText("EMV parsing error: " + uFCoder.status2str(ufr_status));
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}

					tail.next = temp;
					tail = tail.next;


					ufr_status = (uint) uFCoder.getAfl(temp, afl_list_item, afl_list_count);
					if (ufr_status == (uint) UFR_STATUS.EMV_ERR_TAG_NOT_FOUND)
					{
						ufr_status = (uint) uFCoder.getAflFromResponseMessageTemplateFormat1(temp, afl_list_item, afl_list_count);
					}

					if (ufr_status != 0)
					{
						txtReadEMV.AppendText("EMV parsing error: " + uFCoder.status2str(ufr_status));
						txtStatus.Text = uFCoder.status2str(ufr_status);
						break;
					}

					while (afl_list_item[0] != null)
					{
						for (int r = afl_list_item[0].record_first[0]; r <= afl_list_item[0].record_last[0]; r++)
						{
							++cnt;
							txtReadEMV.AppendText("\n " + cnt.ToString() + ". Issuing \"Read Record\" command (record = " + r.ToString() + ", sfi = " + afl_list_item[0].sfi[0].ToString() + "):\n  [C] 00 B2 " + r.ToString("X2") + " " + ((afl_list_item[0].sfi[0] << 3) | 4).ToString("X2") + "\n");
							
							ufr_status = (uint)uFCoder.emvReadRecord(r_apdu, Ne_ptr, afl_list_item[0].sfi[0], (byte)r, sw);
							if (ufr_status == 0)
							{
								int[] temp_Ne = new int[Ne_ptr.Length];
								Array.Copy(Ne_ptr, 0, temp_Ne, 0, Ne_ptr.Length);

								byte[] temp_resp = new byte[r_apdu.Length];
								Array.Copy(r_apdu, 0, temp_resp, 0, r_apdu.Length);

								temp = uFCoder.newEmvTag(temp, temp_resp, temp_Ne, false, emv_status);
								if (emv_status[0] == 0)
								{
									tail.next = temp;
									tail = tail.next;
								}

								if (Ne_ptr[0] > 0)
								{
									txtReadEMV.AppendText(" APDU command executed: response data length = " + Ne_ptr[0] + " bytes\n");
									txtReadEMV.AppendText(" [R] ");
									for (int i = 0; i < Ne_ptr[0]; i++)
									{
										txtReadEMV.AppendText(r_apdu[i].ToString("X2") + " ");
									}
								}
								txtReadEMV.AppendText("\n [SW] " + sw[0].ToString("X2") + " " + sw[1].ToString("X2") + " ");

							}
						}
						afl_list_item[0] = afl_list_item[0].next;
					}
				}

				ufr_status = 0;
				txtStatus.Text = uFCoder.status2str(ufr_status);
			} while (false);


			uFCoder.s_block_deselect((byte)100);
		}

        private void btnClearReadEMV_Click(object sender, RoutedEventArgs e)
        {
			txtReadEMV.Clear();
        }

		private void chkAdvanced_Click(object sender, RoutedEventArgs e)
		{
			grpAdvancedOptions.IsEnabled = (bool) chkAdvanced.IsChecked;
		}
	}
}
