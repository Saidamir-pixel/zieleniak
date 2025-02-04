var animateButton = function (e) {
  e.target.classList.toggle('animate');
  setTimeout(function () {
    e.target.classList.remove('animate');
  }, 700);
};

var bubblyButtons = document.getElementsByClassName("bubbly-button");

for (var i = 0; i < bubblyButtons.length; i++) {
  bubblyButtons[i].addEventListener('click', animateButton, false);
}

document.addEventListener('DOMContentLoaded', function () {
  const burger = document.querySelector('.burger-menu');
  const links = document.querySelector('.links');

  burger.addEventListener('click', function () {
      burger.classList.toggle('active'); // Добавляет анимацию к линиям бургер-меню
      links.classList.toggle('active'); // Управление видимостью меню
  });
});


