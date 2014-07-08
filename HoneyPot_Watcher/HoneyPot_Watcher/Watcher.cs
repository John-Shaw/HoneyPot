using System;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.IO;
using System.Net;
using System.Text;
using System.Windows.Forms;
using MySql.Data;
using MySql.Data.MySqlClient;



namespace HoneyPot_Watcher
{
    public partial class Watcher : Form
    {
        public Watcher()
        {
            InitializeComponent();

            
            WatcherPath = fileSystemWatcher1.Path;
            WatcherFilter = fileSystemWatcher1.Filter;
            WatcherInterval = timer1.Interval;
            CanWatchDB = true;
           
        }


        private MySqlConnection conn = null;
        private string MyConnectionString = "server=192.168.0.109;uid=honeypot;pwd=qweewq;database=log;pooling=true";
        public bool isUpLog { get; set; }


        /// <summary>
        /// 上传日志
        /// </summary>
        /// <param name="log"></param>
        /// <param name="type">type {0: 未定义; 1: 磁盘监控; 2: 数据库监控; 3: 待分析}</param>
        private void upLogs(string log,int type)
        {
           
            try
            {
                conn = new MySqlConnection(MyConnectionString);
                conn.Open();
                string query = string.Format("insert into http_log(content,type) values('{0}',{1})", log, type);
                
                MySqlCommand cmd = new MySqlCommand(query, conn);
                cmd.ExecuteNonQuery();

            }
            catch (MySqlException ex)
            {
                MessageBox.Show(ex.Message);
            }
            finally
            {
                conn.Close();
            }
        }


        /// <summary>
        /// 磁盘监控事件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void onChanged(object sender, FileSystemEventArgs e)
        {
            string log, uplog;
            try
            {
                log = "Time:" + DateTime.Now + " File [" + e.ChangeType + "] Path: " + e.FullPath;
                listBox1.Items.Add(log);
                uplog = string.Format(" File " + e.ChangeType + " Path: " + e.FullPath);
                upLogs(uplog, 1);
            }
            catch (WebException wex)
            {
                MessageBox.Show(wex.ToString());
            }
        }

        /// <summary>
        /// 磁盘监控事件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void onCreated(object sender, FileSystemEventArgs e)
        {
            string log, uplog;
            try
            {
                log = "Time:" + DateTime.Now + " File [" + e.ChangeType + "] Path: " + e.FullPath;
                listBox1.Items.Add(log);
                uplog = string.Format(" File " + e.ChangeType + " Path: " + e.FullPath);
                upLogs(uplog, 1);
            }
            catch (WebException wex)
            {
                MessageBox.Show(wex.ToString());
            }
        }

        /// <summary>
        /// 磁盘监控事件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void onDeleted(object sender, FileSystemEventArgs e)
        {
            string log, uplog;
            try
            {
                log = "Time:" + DateTime.Now + " File [" + e.ChangeType + "] Path: " + e.FullPath;
                listBox1.Items.Add(log);
                uplog = string.Format(" File " + e.ChangeType + " Path: " + e.FullPath);
                upLogs(uplog, 1);
            }
            catch (WebException wex)
            {
                MessageBox.Show(wex.ToString());
            }
        }

        /// <summary>
        /// 磁盘监控事件
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void onRenamed(object sender, RenamedEventArgs e)
        {

            string log, uplog;
            try
            {
                log = "Time:" + DateTime.Now + " File "+ e.OldName + " [renamed to] " + e.Name + " Old Path: " + e.FullPath + " To New Path" + e.OldFullPath;
                listBox1.Items.Add(log);
                uplog = string.Format(" File [" + e.OldName + "] [renamed to] [" + e.Name + "] Path: " + e.FullPath + " Old Path" + e.OldFullPath);
                upLogs(uplog,1);
            }
            catch (WebException wex)
            {
                MessageBox.Show(wex.ToString());
            }
        }

        /// <summary>
        /// 开启监控
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void toolStripButton1_Click(object sender, EventArgs e)
        {
            fileSystemWatcher1.EnableRaisingEvents = true;
            listBox1.Items.Add("start watcher");
            listBox1.Items.Add("监控开启中..........");

            if (CanWatchDB)
            {
                timer1.Start();
            }
        }


        /// <summary>
        /// 关闭监控
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void toolStripButton2_Click(object sender, EventArgs e)
        {

            fileSystemWatcher1.EnableRaisingEvents = false;

            timer1.Stop();
        }


        /// <summary>
        /// 清空listbox
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void toolStripButton3_Click(object sender, EventArgs e)
        {
            toolStripButton2.PerformClick();
            listBox1.Items.Clear();
            toolStripButton1.PerformClick();
        }


        /// <summary>
        /// 监控数据库
        /// </summary>
        private int _lastCountLogs = 0;
        private int _currentCountLogs = 0;

        private void watchDB()
        {
            _currentCountLogs = countLogs();
            if (_lastCountLogs == 0)
            {
                string sql = @"SELECT       allocunitname,operation,[RowLog Contents 0] as r0,[RowLog Contents 1] as r1 
                                            from::fn_dblog (null, null)  
                                            where allocunitname like 'dbo.log_test%' and
                                            operation in('LOP_INSERT_ROWS','LOP_DELETE_ROWS')";
                ExeSqlCommand(sql);
                _lastCountLogs = _currentCountLogs;
            }
            else if (_lastCountLogs < _currentCountLogs)
            {
                int plusLogs = _currentCountLogs - _lastCountLogs;
                string sql = string.Format(@"SELECT  top {0} allocunitname,operation,[RowLog Contents 0] as r0,[RowLog Contents 1] as r1 
                                            from::fn_dblog (null, null)  
                                            where allocunitname like 'dbo.log_test%' and
                                            operation in('LOP_INSERT_ROWS','LOP_DELETE_ROWS')
                                            order by [Current LSN] desc", plusLogs);
                ExeSqlCommand(sql);
                _lastCountLogs = _currentCountLogs;
            }
            else
            {
                return;
            }

        }

        private int countLogs()
        {
            Int32 counter = 0;
            string countSqlComm = @"select count(*) from ::fn_dblog (null, null)
                                    where allocunitname like 'dbo.log_test%' and
                                    operation in('LOP_INSERT_ROWS','LOP_DELETE_ROWS')";
            using (System.Data.SqlClient.SqlConnection conn = new System.Data.SqlClient.SqlConnection())
            {

                conn.ConnectionString = "Data Source=DEV-PC\\SQLEXPRESS;Initial Catalog=dbLogTest;Integrated Security=True";
                conn.Open();

                System.Data.SqlClient.SqlCommand command = new System.Data.SqlClient.SqlCommand(countSqlComm, conn);

                counter = Convert.ToInt32(command.ExecuteScalar());

                conn.Close();
            }
            //MessageBox.Show(counter.ToString());
            return counter;

        }

        private void ExeSqlCommand(string sql)
        {

            using (System.Data.SqlClient.SqlConnection conn = new System.Data.SqlClient.SqlConnection())
            {
                conn.ConnectionString = "Data Source=DEV-PC\\SQLEXPRESS;Initial Catalog=dbLogTest;Integrated Security=True";
                conn.Open();
                using (System.Data.SqlClient.SqlCommand command = conn.CreateCommand())
                {

                    //察看dbo.log_test对象的sql日志
                    command.CommandText = sql;

                    System.Data.SqlClient.SqlDataReader reader = command.ExecuteReader();
                    //根据表字段的顺序建立字段数组,
                    Datacolumn[] columns = new Datacolumn[]
                        {
                            new Datacolumn("id", System.Data.SqlDbType.Int),
                            new Datacolumn("code", System.Data.SqlDbType.Char,10),
                            new Datacolumn("name", System.Data.SqlDbType.VarChar),
                            new Datacolumn("date", System.Data.SqlDbType.DateTime),
                            new Datacolumn("memo", System.Data.SqlDbType.VarChar)
                        };
                    //循环读取日志
                    while (reader.Read())
                    {

                        byte[] data = (byte[])reader["r0"];
                        //byte[] data2 = (byte[])reader["r1"];
                        try
                        {
                            //把二进制数据结构转换为明文
                            TranslateData(data, columns);
                            //TranslateData(data2, columns);
                            string log = string.Format("ip xxxxx 对表{1}进行了{0}操作：", reader["operation"], reader["allocunitname"]);
                            listBox1.Items.Add(log);
                            listBox1.Items.Add("改动数据如下");
                            //Console.WriteLine("数据对象{1}的{0}操作：", reader["operation"], reader["allocunitname"]);
                            foreach (Datacolumn c in columns)
                            {
                                listBox1.Items.Add(string.Format("{0} = {1}", c.Name, c.Value));
                                //Console.WriteLine("{0} = {1}", c.Name, c.Value);
                            }
                            listBox1.Items.Add("[Stop]");
                            upLogs(log, 2);
                        }
                        catch (Exception ex)
                        {
                            MessageBox.Show(ex.Message);
                        }

                    }
                    reader.Close();
                }
                conn.Close();
            }
        }

        /// <summary>
        /// sql二进制结构翻译，这个比较关键，测试环境为sql2005，其他版本没有测过。
        /// </summary>
        /// <param name="data"></param>
        /// <param name="columns"></param>
        static void TranslateData(byte[] data, Datacolumn[] columns)
        {
            //我只根据示例写了Char,DateTime,Int三种定长度字段和varchar一种不定长字段，其余的有兴趣可以自己补充
            //这里没有暂时没有考虑Null和空字符串两种情况，以后会补充。

            //引用请保留以下信息：
            //作者：jinjazz 
            //sql的数据行二进制结构参考我的blog
            //http://blog.csdn.net/jinjazz/archive/2008/08/07/2783872.aspx
            //行数据从第5个字节开始
            short index = 4;
            //先取定长字段
            foreach (Datacolumn c in columns)
            {
                switch (c.DataType)
                {
                    case System.Data.SqlDbType.Char:
                        //读取定长字符串，需要根据表结构指定长度
                        c.Value = System.Text.Encoding.Default.GetString(data, index, c.Length);
                        index += c.Length;
                        break;
                    case System.Data.SqlDbType.DateTime:
                        //读取datetime字段，sql为8字节保存
                        System.DateTime date = new DateTime(1900, 1, 1);
                        //前四位1/300秒保存
                        int second = BitConverter.ToInt32(data, index);
                        date = date.AddSeconds(second / 300);
                        index += 4;
                        //后四位1900-1-1的天数
                        int days = BitConverter.ToInt32(data, index);
                        date = date.AddDays(days);
                        index += 4;
                        c.Value = date;
                        break;
                    case System.Data.SqlDbType.Int:
                        //读取int字段,为4个字节保存
                        c.Value = BitConverter.ToInt32(data, index);
                        index += 4;
                        break;
                    default:
                        //忽略不定长字段和其他不支持以及不愿意考虑的字段
                        break;
                }
            }
            //跳过三个字节
            index += 3;
            //取变长字段的数量,保存两个字节
            short varColumnCount = BitConverter.ToInt16(data, index);
            index += 2;
            //接下来,每两个字节保存一个变长字段的结束位置,
            //所以第一个变长字段的开始位置可以算出来
            short startIndex = (short)(index + varColumnCount * 2);
            //第一个变长字段的结束位置也可以算出来
            short endIndex = BitConverter.ToInt16(data, index);
            //循环变长字段列表读取数据
            foreach (Datacolumn c in columns)
            {
                switch (c.DataType)
                {
                    case System.Data.SqlDbType.VarChar:
                        //根据开始和结束位置，可以算出来每个变长字段的值
                        c.Value = System.Text.Encoding.Default.GetString(data, startIndex, endIndex - startIndex);
                        //下一个变长字段的开始位置
                        startIndex = endIndex;
                        //获取下一个变长字段的结束位置
                        index += 2;
                        endIndex = BitConverter.ToInt16(data, index);
                        break;
                    default:
                        //忽略定长字段和其他不支持以及不愿意考虑的字段
                        break;
                }
            }
            //获取完毕
        }


        /// <summary>
        /// 监控数据库tick
        /// </summary>
        /// <param name="sender"></param>
        /// <param name="e"></param>
        private void timer1_Tick(object sender, EventArgs e)
        {
            watchDB();
        }



        public string WatcherPath { set; get; }
        public string WatcherFilter {set; get; }
        public int WatcherInterval { set; get; }
        public bool CanWatchDB { set; get; }

        private void toolStripButton4_Click(object sender, EventArgs e)
        {
            
            new SettingsForm(this)
            {

            }.Show();

        }

        public void changeProperties()
        {

            fileSystemWatcher1.Path = WatcherPath;
            fileSystemWatcher1.Filter = WatcherFilter;
            timer1.Interval = WatcherInterval;

            if(!CanWatchDB)
            {
                timer1.Enabled = false;
            }
            else
            {
                timer1.Enabled = true;
            }

        }


    }
}
