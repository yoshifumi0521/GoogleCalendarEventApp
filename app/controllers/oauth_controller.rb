#coding: utf-8
#ライブラリを読む
require "libraries/google_auth_sub"

#oauth認証をするためのクラス
class OauthController < ApplicationController
   
  def get
    #GoogleAuthSubクラスのgetURLForAuthSubRequestメソッドを実行
    @uri = GoogleAuthSub.getURLForAuthSubRequest(
      "https://www.google.com/calendar/feeds/",
      "http://localhost:3000/oauth/callback"
    ) 

    #Googleにリダイレクトする
    redirect_to @uri

  
  end

  #リダイレクトしてかえってきたらする処理。 
  def callback
    logger.debug("かえってきたーー")


  
  
  end



end
