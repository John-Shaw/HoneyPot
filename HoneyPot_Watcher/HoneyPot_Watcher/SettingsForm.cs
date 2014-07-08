using System;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Text;
using System.Windows.Forms;

namespace HoneyPot_Watcher
{
    public partial class SettingsForm : Form
    {
        public SettingsForm(Watcher watcher)
        {
            InitializeComponent();
            _watcher = watcher;
            textBox1.Text = watcher.WatcherPath;
            comboBox1.Text = watcher.WatcherFilter;
            textBox3.Text = (watcher.WatcherInterval).ToString();
            checkBox1.Checked = !watcher.CanWatchDB;
        }

        private Watcher _watcher;

        private void button1_Click(object sender, EventArgs e)
        {


            DialogResult result = folderBrowserDialog1.ShowDialog();


            if (result == DialogResult.OK)
            {
                this.textBox1.Text = folderBrowserDialog1.SelectedPath;
            }
        }

        private void button3_Click(object sender, EventArgs e)
        {
            if(textBox1.Text != "")
            {
                _watcher.WatcherPath = textBox1.Text;
            }
            if(comboBox1.Text != "")
            {
                _watcher.WatcherFilter = comboBox1.Text;
            }
            if(textBox3.Text != "")
            {
                _watcher.WatcherInterval = Convert.ToInt32(textBox3.Text);
            }
            if(checkBox1.Checked == true)
            {
                _watcher.CanWatchDB = false;
            }
            else
            {
                _watcher.CanWatchDB = true;
            }


            _watcher.changeProperties();

            this.Close();
        }

        private void button5_Click(object sender, EventArgs e)
        {
            textBox1.Text = "";
            comboBox1.Text = "";
            textBox3.Text = "";
        }

    }
}
