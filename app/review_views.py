from app.models import ReviewCategories, CourseReview, Course, ReviewReaction
from app.views_dependency import *
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated
from rest_framework.pagination import PageNumberPagination
from app.review_utils import CourseReviewSerializer, get_course_data_for_frontend, CourseReviewListSerializer, CourseReviewPagination, CourseInfoSerializer
import json
from rest_framework import status
from rest_framework.response import Response

@login_required(redirect_field_name="origin")
@utils.check_user_access(redirect_url="/logout/")
@logger.secure_view()
def coursesOverview(request):
    bar_display = utils.get_sidebar_and_navbar(
        request.user, navbar_name="课程测评", title_name="课程评价"
    )
    json_data = [
        {'category':'德', 'courses': []},
        {'category':'智', 'courses': []},
        {'category':'体', 'courses': []},
        {'category':'美', 'courses': []},
        {'category':'劳', 'courses': []},
    ]
    all_courses = ReviewCategories.objects.all().values_list('id', 'course_name', 'course_type')
    for cid, name, category in all_courses:
        category = Course.CourseType.labels[category]
        for item in json_data:
            if item['category'] == category:
                review_count = CourseReview.objects.filter(course__id=cid).count()
                item['courses'].append({'id': cid, 'name': name, 'review_count': review_count})
                break
    json_str = json.dumps(json_data, ensure_ascii=False)

    vars = {
        "bar_display": bar_display,
        "json_data": json_str,
    }
    return render(request, "review/coursesOverview.html", vars)

class CourseInfoAPIView(APIView):
    """返回课程的评分统计数据"""
    queryset = CourseReview.objects.all()
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        courseID = self.request.GET.get("id", None)
        if courseID:
            try:
                course = ReviewCategories.objects.get(id=courseID)
                return CourseReview.objects.filter(course=course)
            except ReviewCategories.DoesNotExist:
                return CourseReview.objects.none()
        return CourseReview.objects.none()
    
    def get(self, request):
        courseID = request.GET.get("id", None)
        REVIEW_PER_PAGE = 5

        if not courseID:
            return Response({"error": "缺少参数"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            course = ReviewCategories.objects.get(id=courseID)
        except ReviewCategories.DoesNotExist:
            return Response({"error": "课程不存在"}, status=status.HTTP_400_BAD_REQUEST)
        
        reviews = CourseReview.objects.filter(course=course).values_list("semester","school_year", "rating_recommend", "rating_content", "rating_workload", "rating_grade")
        reviews_formated = {}
        conversion = {'Spring': 1, 'Fall' : 2}
        
        # Collect all reviews for overall calculation
        all_reviews = []
        
        for semester, year, r1, r2, r3, r4 in reviews:
            semester_s = f"{year}-{year+1}-{conversion[semester]}"
            if semester_s not in reviews_formated:
                reviews_formated[semester_s] = []
            reviews_formated[semester_s].append((r1, r2, r3, r4))
            all_reviews.append((r1, r2, r3, r4))
        
        # Calculate overall averages
        def calculate_average(ratings_list, index):
            values = [rating[index] for rating in ratings_list if rating[index] is not None]
            return round(sum(values) / len(values), 1) if values else 0
        
        overall = {
            'recommend': calculate_average(all_reviews, 0),
            'content': calculate_average(all_reviews, 1),
            'workload': calculate_average(all_reviews, 2),
            'grade': calculate_average(all_reviews, 3)
        }
        
        # Calculate semester averages
        semesters = []
        for semester_name, semester_reviews in reviews_formated.items():
            semester_data = {
                'name': semester_name,
                'recommend': calculate_average(semester_reviews, 0),
                'content': calculate_average(semester_reviews, 1),
                'workload': calculate_average(semester_reviews, 2),
                'grade': calculate_average(semester_reviews, 3)
            }
            semesters.append(semester_data)
        
        # Sort semesters by name for consistent ordering
        semesters.sort(key=lambda x: x['name'])

        # Handle review pagination
        total_pages = (len(reviews) + REVIEW_PER_PAGE - 1) // REVIEW_PER_PAGE

        data = {
            "overall": overall, 
            "semesters": semesters, 
            "total_pages": total_pages
        }
        
        serializer = CourseInfoSerializer(data)
        return Response(serializer.data)

class CourseReviewsAPIView(APIView):
    """返回课程的评价列表"""
    queryset = CourseReview.objects.all()
    permission_classes = [IsAuthenticated]
    
    def get_queryset(self):
        courseID = self.request.GET.get("id", None)
        if courseID:
            try:
                course = ReviewCategories.objects.get(id=courseID)
                return CourseReview.objects.filter(course=course).order_by('-time')
            except ReviewCategories.DoesNotExist:
                return CourseReview.objects.none()
        return CourseReview.objects.none()
    
    def get(self, request):
        courseID = request.GET.get("id", None)
        
        if not courseID:
            return Response({"error": "缺少参数"}, status=status.HTTP_400_BAD_REQUEST)
        
        try:
            course = ReviewCategories.objects.get(id=courseID)
        except ReviewCategories.DoesNotExist:
            return Response({"error": "课程不存在"}, status=status.HTTP_400_BAD_REQUEST)
        
        reviews = self.get_queryset()
        
        # Use DRF pagination
        paginator = CourseReviewPagination()
        paginated_reviews = paginator.paginate_queryset(reviews, request)
        
        if paginated_reviews is None:
            # No reviews found
            return Response({"reviews": []})
        
        serializer = CourseReviewListSerializer(paginated_reviews, many=True, context={'request': request})
        return Response({"reviews": serializer.data})

@login_required(redirect_field_name="origin")
@utils.check_user_access(redirect_url="/logout/")
@logger.secure_view()
def postReview(request):
    if request.method == "POST":
        serializer = CourseReviewSerializer(
            data=request.POST,
            context={'request': request}
        )
        if serializer.is_valid():
            try:
                # Create the review
                review = serializer.save()

                # Redirect to course overview
                url = reverse("coursesOverview")
                return redirect(f"{url}?msg=发布成功&id={serializer.validated_data['course'].id}")

            except Exception as e:
                # Handle any database errors
                html_display = wrong("发布失败，请联系管理员或重试")
        else:
            # Validation errors
            error_messages = []
            for field, errors in serializer.errors.items():
                for error in errors:
                    error_messages.append(f"{error}")
            
            html_display = wrong("请检查输入内容：" + "；".join(error_messages))
            
        
        bar_display = utils.get_sidebar_and_navbar(
            request.user, navbar_name="课程测评", title_name="发表测评"
        )
        json_data = get_course_data_for_frontend()
        json_str = json.dumps(json_data, ensure_ascii=False)

        vars = {
            "json_data": json_str,
            "bar_display": bar_display,
            "html_display": html_display
        }

        return render(request, "review/postReview.html", vars)

    elif request.method == "GET":
        # GET request - display the form
        bar_display = utils.get_sidebar_and_navbar(
            request.user, navbar_name="课程测评", title_name="发表测评"
        )
        
        # Use the utility function from review_utils
        json_data = get_course_data_for_frontend()
        json_str = json.dumps(json_data, ensure_ascii=False)

        vars = {
            "json_data": json_str,
            "bar_display": bar_display
        }

        return render(request, "review/postReview.html", vars)
    else:
        return redirect("welcome")
    

class ReviewLikeAPI(APIView):
    """处理课程评价的点赞和点踩"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        review_id = request.data.get("review_id")
        action = request.data.get("action")  # 'like' or 'dislike'

        if not review_id or action not in ['like', 'dislike']:
            return Response({"error": "缺少参数或参数错误"}, status=status.HTTP_400_BAD_REQUEST)

        try:
            review = CourseReview.objects.get(id=review_id)
        except CourseReview.DoesNotExist:
            return Response({"error": "评价不存在"}, status=status.HTTP_400_BAD_REQUEST)

        user = request.user

        if action == 'like':
            ReviewReaction.objects.update_or_create(
                user=user, review=review,
                defaults={'reaction': ReviewReaction.ReactionType.LIKE}
            )
        else:  # action == 'dislike'
            ReviewReaction.objects.update_or_create(
                user=user, review=review,
                defaults={'reaction': ReviewReaction.ReactionType.DISLIKE}
            )
        
        data = {
            'likes': review.reactions.filter(reaction=ReviewReaction.ReactionType.LIKE).count(),
            'dislikes': review.reactions.filter(reaction=ReviewReaction.ReactionType.DISLIKE).count(),
            'liked': ReviewReaction.objects.filter(user=user, review=review, reaction=ReviewReaction.ReactionType.LIKE).exists(),
            'disliked': ReviewReaction.objects.filter(user=user, review=review, reaction=ReviewReaction.ReactionType.DISLIKE).exists()
        }

        return Response(data)