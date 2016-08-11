using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Web;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;
using System.IO;

namespace xAuthBellaDati
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        BellaDatiConnection connection = new BellaDatiConnection("https://service.belladati.com");
        public MainWindow()
        {
            InitializeComponent();

        }

        private void Button_Click(object sender, RoutedEventArgs e)
        {
            //This is how you would setup the object if you already had the token and secret.
            //oAuthTwitter oAuth = new oAuthTwitter();
            //oAuth.Token = token;
            //oAuth.TokenSecret = tokensecret;

            try
            {
                connection.xAuthGetAccessToken(textBoxName.Text, pswdBox.Password);
                //Save oAuth.Token & oAuth.TokenSecret at this point.
                //You can reuse the tokens unless the user revokes access to your application.

                string data = connection.doGet("/api/reports/");
                textBlockResponse.Text = data;
            }
            catch (Exception ee)
            {
                textBlockResponse.Text = ee.Message;
            }

        }

        private void Button_Click_1(object sender, RoutedEventArgs e)
        {
            try
            {
             //id is identification number of your report//   string data = connection.doGet("/api/reports/views/id/image");
                var uri = new Uri(@"C:\chart.png");
                var bitmap = new BitmapImage(uri);
                pictureBox.Source = bitmap;
            }
            catch (Exception ee)
            {
                textBlockResponse.Text = ee.Message;
            }
        }
    }
}
