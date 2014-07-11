using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;
using MySql.Data;
using MySql.Data.MySqlClient;
using System.Net;
using System.IO;

namespace HoneyPot_Manager
{
    public partial class Manager : Form
    {
        public Manager()
        {
            InitializeComponent();


            ListViewItem lvi = new ListViewItem();

            
            #region 测试用

            //player = new System.Media.SoundPlayer(Properties.Resources.ALARM3);
            //MessageBox.Show(" test Github sync branc,if you see it,it done");

            
            //string[] splieStrings = { "[Stop]" };
            //string[] Logs = Properties.Resources.logtest.Split(splieStrings, System.StringSplitOptions.RemoveEmptyEntries);

            //foreach(string log in Logs)
            //{
            //    if(SQL_injection1(log))
            //    {
            //        listView1.Items.Add(_Temp);
            //    }

            //}

            #endregion
        }




        #region 所有实例变量
        private MySqlConnection conn = null;

        /// <summary>
        /// 数据库连接字符串
        /// </summary>
        private string MyConnectionString = "server=192.168.0.109;uid=honeypot;pwd=qweewq;database=log;pooling=true";

        private int _CurrentID = 0;
        private int _CurrentIDFromHacker = 0;

        private string[] XSS = Properties.Resources.XSS关键词.Split('\n');
        private static string[] sql_normal = Properties.Resources.SQL_普通注入.Split('\n');
        private static string[] sql_attack = Properties.Resources.SQL_攻击存储过程.Split('\n');
        private string _sqlInjection_Commen = "SQL普通注入 ";
        private string _sqlInjection_Proc = "SQL攻击存储过程 ";

        private string _POST = "POST提交 ";
        private string _GET = "GET提交 ";

        private string XSS_cookie = "document.cookie";
        private string XSS_fish = "document.forms[0]";

        string[] oneWordShell = { "request", "eval", "exectue" };
        string[] fileOpre = { "fopen", "fclose", "fgets" };

        private System.Media.SoundPlayer player;

        #endregion



        #region 与数据库的信息交互
        /// <summary>
        /// 返回最新ID
        /// </summary>
        /// <returns></returns>
        private int getLastID()
        {
            int lastid = 0;
            try
            {
                conn = new MySqlConnection(MyConnectionString);
                conn.Open();
                string query = string.Format("select id from http_log order by id desc limit 1"); 
                
                MySqlCommand cmd = new MySqlCommand(query, conn);

                lastid = (int)cmd.ExecuteScalar();
            }
            catch(MySqlException ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                conn.Close();
            }
            return lastid;
        }

        /// <summary>
        /// 返回最新ID
        /// </summary>
        /// <returns></returns>
        private int getLastIDFromHacker()
        {
            int lastid = 0;
            try
            {
                conn = new MySqlConnection(MyConnectionString);
                conn.Open();
                string query = string.Format("select idhackersInfo from hackersInfo order by id desc limit 1");

                MySqlCommand cmd = new MySqlCommand(query, conn);

                lastid = (int)cmd.ExecuteScalar();
            }
            catch (MySqlException ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                conn.Close();
            }
            return lastid;
        }


        /// <summary>
        /// 读取反渗透信息
        /// </summary>
        /// <param name="id"></param>
        private void readHackersInfo(int id)
        {
            int lastid = getLastID();

            if (lastid <= _CurrentIDFromHacker)
            {
                return;
            }

            MySqlDataReader reader = null;

            try
            {

                conn = new MySqlConnection(MyConnectionString);
                conn.Open();
                string query = string.Format("select idhackersInfo,HackersIP, HackersDomain,HackersDiskNum,HackersName from hackersInfo where id > {0} order by id limit 20", id);


                MySqlCommand cmd = new MySqlCommand(query, conn);
                reader = cmd.ExecuteReader();


                while (reader.Read())
                {

                    ListViewItem lvi = new ListViewItem();

                    lvi.Text = reader["HackersIP"].ToString();
   

                    lvi.SubItems.AddRange(new string[] {                                                       
                                                            reader["HackersName"].ToString(),
                                                            reader["HackersDomain"].ToString(),
                                                            reader["HackersDiskNum"].ToString()
                                                       });
                    listView4.Items.Add(lvi);
                }

                _CurrentIDFromHacker = (int)reader["idhackersInfo"];


            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                reader.Close();
                conn.Close();
            }
        }


        /// <summary>
        /// 从服务器数据库读取日志
        /// </summary>
        /// <param name="id"></param>
        private void readLogs(int id)
        {
            int lastid = getLastID();

            if(lastid <= _CurrentID)
            {
                return;
            }

            MySqlDataReader reader = null;
            int type = 0;
            string analysis = "";

            try
            {

                conn = new MySqlConnection(MyConnectionString);
                conn.Open();
                string query = string.Format("select id,logTime, content,sourceIP,type from http_log where id > {0} order by id limit 20",id);


                MySqlCommand cmd = new MySqlCommand(query, conn);
                reader = cmd.ExecuteReader();


                while (reader.Read())
                {
                    
                    type = (int)reader["type"];

                    if (type == 0 || type == 3)
                    {
                        ListViewItem lvi = new ListViewItem();


                        lvi.Text = reader["logTime"].ToString();

                        analysis = log_analysis(reader["content"].ToString());
                        if(analysis == "")
                        {
                            analysis = "unknow";
                        }

                        lvi.SubItems.AddRange(new string[] {                                                              
                                                            reader["sourceIP"].ToString(),
                                                            analysis,
                                                            reader["content"].ToString()
                                                       });
                        listView1.Items.Add(lvi);
                    }
                    else
                    {
                        ListViewItem lvi = new ListViewItem();

                        lvi.Text = reader["logTime"].ToString();
                        if (type == 1)
                        {
                            analysis = "磁盘文件操作";
                        }
                        else if(type == 2)
                        {
                            analysis = "数据库操作";
                        }

                        lvi.SubItems.AddRange(new string[] {                                                       
                                                            reader["sourceIP"].ToString(),
                                                            analysis,
                                                            reader["content"].ToString()
                                                       });
                        listView1.Items.Add(lvi);
                    }
                }

                _CurrentID = (int)reader["id"];


            }
            catch (Exception ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                reader.Close();
                conn.Close();
            }
        }


        #endregion


        #region 各种控件注册事件
        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            timer1.Start();
        }

        private void timer1_Tick(object sender, EventArgs e)
        {
            readLogs(_CurrentID);
        }

        private void toolStripButton2_Click(object sender, EventArgs e)
        {
            timer1.Stop();
        }

        private void toolStripButton6_Click(object sender, EventArgs e)
        {
            timer2.Start();
        }

        private void timer2_Tick(object sender, EventArgs e)
        {
            readHackersInfo(_CurrentIDFromHacker);
        }


        #endregion

        
        #region  日志分析部分

        private string log_analysis(string log)
        {
            string retlog = "";
            retlog += SQL_injection1(log);
            retlog += SQL_injection2(log);
            retlog += XSS_Attack(log);
            retlog += upLoadShell(log);
            return retlog;
        }

        private string SQL_injection1(string log)
        {
            //player.Stop();
            string temp = "";
            if (sql_normal.Any(s => log.Contains(s)))
            {
                
                if (log.Contains("POST"))
                {
                    temp = _sqlInjection_Commen + _POST;

                }
                else if (log.Contains("GET"))
                {
                    temp = _sqlInjection_Commen + _GET;
                }
                else
                {
                    temp =  _sqlInjection_Commen;
                }
                //player.Play();
                
                return temp;
            }
            return "";
        }

        private string SQL_injection2(string log)
        {
            //player.Stop();
            string temp = "";
            if (sql_attack.Any(log.Contains))
            {
                
                if (log.Contains("POST"))
                {
                    temp = _sqlInjection_Proc + _POST;

                }
                else if (log.Contains("GET"))
                {
                    temp = _sqlInjection_Proc + _GET;
                }
                else
                {
                    temp = _sqlInjection_Proc;
                }
                //player.Play();
                return temp;
            }
            return "";
        }



        private string XSS_Attack(string log)
        {
            string temp = "";
            if (XSS.Any(log.Contains))
            {

                if (log.Contains(XSS_cookie))
                {
                    temp = "XSS注入 cookie攻击 ";
                }
                else if (log.Contains(XSS_fish))
                {
                    temp = "XSS注入 跨站钓鱼攻击";
                }
                else
                {
                    temp = "XSS注入 ";
                }
                
                return temp;
            }
            return "";
        }


        private string upLoadShell(string log)
        {
            string temp = "";
            if (log.Length <= 30)
            {
                if(oneWordShell.Any(log.Contains))
                {
                    temp = "一句话木马";
                    return temp;
                }
                
            }
            else
            {
                temp = "上传shell攻击 ";
                if(log.Contains("upload"))
                {
                    temp += "上传";
                    return temp;
                }
                if (fileOpre.Any(log.Contains))
                {
                    temp += "文件操作";
                    return temp;
                }
                if (log.Contains("exec"))
                {
                    temp += "命令执行";
                    return temp;
                }
            }
            return "";
        }

        #endregion 
        
  
        #region 内网管理


        private void Requst(string postData)
        {
            WebRequest request = WebRequest.Create(" http://192.168.0.99:5000/SendData");
            request.Method = "POST";
            //string postData = "Operation=addIP&IPAddr=" + IP + "&destIP=192.168.12.2";
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;
            Stream dataStream = request.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            WebResponse response = request.GetResponse();
             
            dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string responseFromServer = reader.ReadToEnd();
            MessageBox.Show(responseFromServer);
            reader.Close();
            dataStream.Close();
            response.Close();
        }

        private void RequstWithRespon(string postData,ListView lv)
        {

            WebRequest request = WebRequest.Create(" http://192.168.0.99:5000/SendData");
            request.Method = "POST";
            //string postData = "Operation=queryEnemyIP";
            byte[] byteArray = Encoding.UTF8.GetBytes(postData);
            request.ContentType = "application/x-www-form-urlencoded";
            request.ContentLength = byteArray.Length;
            Stream dataStream = request.GetRequestStream();
            dataStream.Write(byteArray, 0, byteArray.Length);
            dataStream.Close();

            WebResponse response = request.GetResponse();
            //listView1.Items.Add(((HttpWebResponse)response).StatusDescription);
            dataStream = response.GetResponseStream();
            StreamReader reader = new StreamReader(dataStream);
            string linetext = "";
            string[] array = new string[2];
            while (!reader.EndOfStream)
            {
                linetext = reader.ReadLine();
                array = linetext.Split(' ');
                //listView1.Items.Add(array[0]);
                ListViewItem lvi = new ListViewItem(array);
                lv.Items.Add(lvi);
            }
        }



        

        private void button1_Click(object sender, EventArgs e)
        {


            new AddIP(this, "addIP")
            {
                StartPosition = FormStartPosition.CenterScreen
            }.Show();




        }

        public void addIP(string type, string ip, string destIP, string destinationHoneypotIP)
        {
            if(type == "addIP")
            {
                string postdata = "Operation=addIP&IPAddr=" + ip + "&destIP=" + destIP + "&destinationHoneypotIP=" + destinationHoneypotIP;

                Requst(postdata);
            }
            if(type == "addProtected")
            {
                string postdata = "Operation=addProtected&gwIP=" + ip + "&nic=ens38" + "&destIP" + destIP + "&destinationHoneypotIP=" + destinationHoneypotIP; ;

                Requst(postdata);
            }
        }

        

        private void button3_Click(object sender, EventArgs e)
        {
            
            string selectIP = "";
            string destIP = "";

            foreach (ListViewItem lvi in listView2.SelectedItems)
            {
                selectIP = lvi.SubItems[0].Text;
                destIP = lvi.SubItems[1].Text;
            }
            string postdata = "Operation=removeIP&IPAddr=" + selectIP + "&destIP=" + destIP;

            Requst(postdata);
        }

        

        private void button2_Click(object sender, EventArgs e)
        {
            listView2.Items.Clear();
            string postdata = "Operation=queryEnemyIP";

            RequstWithRespon(postdata, listView2);
        }

        private void button6_Click(object sender, EventArgs e)
        {
            new AddIP(this, "addProtected")
            {
                StartPosition = FormStartPosition.CenterScreen
            }.Show();
            
        }

        private void button8_Click(object sender, EventArgs e)
        {
            string selectIP = "";
            string destIP = "";

            foreach (ListViewItem lvi in listView3.SelectedItems)
            {
                selectIP = lvi.SubItems[0].Text;
                destIP = lvi.SubItems[1].Text;
            }

            string postdata = "Operation=removeProtected&gwIP=" + selectIP + "&nic=ens38" + "&destIP=" + destIP;
            Requst(postdata);
        }

        private void button7_Click(object sender, EventArgs e)
        {
            listView3.Items.Clear();
            string postdata = "Operation=queryEnemyIP";

            RequstWithRespon(postdata, listView3);
        }

        #endregion

        
    }
}
