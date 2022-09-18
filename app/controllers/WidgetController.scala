package controllers

import javax.inject.Inject

import models.Widget
import play.api.data._
import play.api.i18n._
import play.api.mvc._

import scala.collection._
import java.security.SecureRandom

/**
 * The classic WidgetController using MessagesAbstractController.
 *
 * Instead of MessagesAbstractController, you can use the I18nSupport trait,
 * which provides implicits that create a Messages instance from a request
 * using implicit conversion.
 *
 * See https://www.playframework.com/documentation/2.8.x/ScalaForms#passing-messagesprovider-to-form-helpers
 * for details.
 */

class WidgetController @Inject()(cc: MessagesControllerComponents) extends MessagesAbstractController(cc) {
  import WidgetForm._

  private val widgets = mutable.ArrayBuffer(
    Widget("99999999", 256)
  )

  val elgResults = widgets.map(w => {
    val elg = new ElGamal(w.price, w.name)
    val elgEncrypt = elg.encrypt()
      models.ElgResult(elg.p , elg.g, elg.a, elg.alphaToPowerOfA, elgEncrypt("gamma") , elg.m)

  })



  val text = "AAAAAAAAAAAAAAAAA"
  val key = "AABB09182736CCDD"
  val des = new Des(text, key)

  val cipher = des.encrypt(text, key)
  val decrypt = des.decrypt(cipher, key)




  // The URL to the widget.  You can call this directly from the template, but it
  // can be more convenient to leave the template completely stateless i.e. all
  // of the "WidgetController" references are inside the .scala file.
  private val postUrl = routes.WidgetController.createWidget

  def index = Action {
    Ok(views.html.index())
  }

  def listWidgets = Action { implicit request: MessagesRequest[AnyContent] =>
    // Pass an unpopulated form to the template
    Ok(views.html.listWidgets(widgets.toSeq, elgResults.toSeq, form, postUrl))
  }

  // This will be the action that handles our form post
  def createWidget = Action { implicit request: MessagesRequest[AnyContent] =>
    val errorFunction = { formWithErrors: Form[Data] =>
      // This is the bad case, where the form had validation errors.
      // Let's show the user the form again, with the errors highlighted.
      // Note how we pass the form with errors to the template.
      BadRequest(views.html.listWidgets(widgets.toSeq, elgResults.toSeq, formWithErrors, postUrl))
    }

    val successFunction = { data: Data =>
      // This is the good case, where the form was successfully parsed as a Data object.
      val widget = Widget(name = data.name, price = data.price)
      widgets += widget
      Redirect(routes.WidgetController.listWidgets).flashing("info" -> "Widget added!")
    }

    val formValidationResult = form.bindFromRequest()
    formValidationResult.fold(errorFunction, successFunction)
  }
}
