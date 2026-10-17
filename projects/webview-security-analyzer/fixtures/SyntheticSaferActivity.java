package org.synthetic.lab;
class SyntheticSaferActivity {
  void configure(android.webkit.WebView view) {
    view.getSettings().setJavaScriptEnabled(false);
    view.getSettings().setAllowFileAccess(false);
  }
  void onReceivedSslError(android.webkit.SslErrorHandler handler) {
    handler.cancel();
  }
}
