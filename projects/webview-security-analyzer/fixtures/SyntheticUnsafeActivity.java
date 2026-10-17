package org.synthetic.lab;
class SyntheticUnsafeActivity {
  void configure(android.webkit.WebView view, Object bridge) {
    view.getSettings().setJavaScriptEnabled(true);
    view.getSettings().setAllowFileAccess(true);
    view.addJavascriptInterface(bridge, "LabBridge");
  }
  void onReceivedSslError(android.webkit.SslErrorHandler handler) {
    handler.proceed();
  }
}
